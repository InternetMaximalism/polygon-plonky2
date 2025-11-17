//! WebGPU scaffolding for Merkle tree construction.
//!
//! This module mirrors the CPU Merkle construction in `merkle_tree.rs` but offloads the heavy
//! Poseidon hashing to a WGSL compute shader. The shader expects Goldilocks field elements in
//! Montgomery form (`a * R mod p` with `R = 2^64`). We therefore convert all hash inputs and
//! constants to Montgomery before uploading them to the GPU and convert results back to the
//! canonical representation after read-back.

#![cfg(all(feature = "gpu_merkle", target_arch = "wasm32"))]

use std::cell::RefCell;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::rc::Rc;
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{anyhow, ensure, Result};
use bytemuck::{Pod, Zeroable};
use futures::channel::oneshot;
use once_cell::unsync::OnceCell;
use web_sys::console;
use wgpu::util::DeviceExt;
use wgpu::{BindGroupLayout, Buffer, ComputePipeline, Device, Queue, SubmissionIndex};

use crate::hash::hash_types::{HashOut, RichField, NUM_HASH_OUT_ELTS};
use crate::hash::poseidon::{self, Poseidon, SPONGE_WIDTH};
// Goldilocks modulus and Montgomery parameters.
const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;
const MONTGOMERY_R: u128 = 1u128 << 64;

const BIGINT_LIMBS: usize = 2;
const DIGEST_ELEMENTS: usize = NUM_HASH_OUT_ELTS;
const WORDS_PER_DIGEST: usize = DIGEST_ELEMENTS * BIGINT_LIMBS;
const BYTES_PER_DIGEST: usize = WORDS_PER_DIGEST * std::mem::size_of::<u32>();
const BYTES_PER_BIGINT: usize = BIGINT_LIMBS * std::mem::size_of::<u32>();
const POSEIDON_WIDTH: usize = SPONGE_WIDTH;
const ROUND_CONSTANT_COUNT: usize = POSEIDON_WIDTH * poseidon::N_ROUNDS;

// for `now` for timing
use js_sys::Promise;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

thread_local! {
    /// WebGPU context reused across Merkle tree constructions.
    static GPU_CONTEXT: OnceCell<Rc<MerkleTreeGpuContext>> = OnceCell::new();
}

/// Cached pipeline and device handles required to launch the Merkle compute kernel.
#[derive(Debug)]
pub struct MerkleTreeGpuContext {
    pub device: Rc<Device>,
    pub queue: Rc<Queue>,
    pub merkle_pipeline: Rc<ComputePipeline>,
    pub merkle_bind_group_layout: Rc<BindGroupLayout>,
    pub leaf_pipeline: Rc<ComputePipeline>,
    pub leaf_bind_group_layout: Rc<BindGroupLayout>,
    pub transpose_to_mont_pipeline: Rc<ComputePipeline>,
    pub transpose_to_mont_bind_group_layout: Rc<BindGroupLayout>,

    pub to_canon_pipeline: Rc<ComputePipeline>,
    pub to_canon_bind_group_layout: Rc<BindGroupLayout>,

    pub mds_circ: Buffer,
    pub mds_diag: Buffer,
    pub round_constants: Buffer,

    // Cached staging buffer for readbacks (web: reused to avoid churn)
    pub readback_staging: RefCell<Option<Buffer>>,
    pub readback_capacity: RefCell<u64>,
}

impl MerkleTreeGpuContext {
    fn new(
        device: Device,
        queue: Queue,
        merkle_pipeline: ComputePipeline,
        merkle_bind_group_layout: BindGroupLayout,
        leaf_pipeline: ComputePipeline,
        leaf_bind_group_layout: BindGroupLayout,
        transpose_to_mont_pipeline: ComputePipeline,
        transpose_to_mont_bind_group_layout: BindGroupLayout,

        to_canon_pipeline: ComputePipeline,
        to_canon_bind_group_layout: BindGroupLayout,

        mds_circ: Buffer,
        mds_diag: Buffer,
        round_constants: Buffer,
    ) -> Self {
        let device = Rc::new(device);
        device.on_uncaptured_error(Box::new(|error| {
            #[cfg(target_arch = "wasm32")]
            {
                web_sys::console::error_1(
                    &format!("⚠️ WebGPU uncaptured error in Merkle context: {error:?}").into(),
                );
            }
        }));

        Self {
            device,
            queue: Rc::new(queue),
            merkle_pipeline: Rc::new(merkle_pipeline),
            merkle_bind_group_layout: Rc::new(merkle_bind_group_layout),
            leaf_pipeline: Rc::new(leaf_pipeline),
            leaf_bind_group_layout: Rc::new(leaf_bind_group_layout),
            transpose_to_mont_pipeline: Rc::new(transpose_to_mont_pipeline),
            transpose_to_mont_bind_group_layout: Rc::new(transpose_to_mont_bind_group_layout),
            to_canon_pipeline: Rc::new(to_canon_pipeline),
            to_canon_bind_group_layout: Rc::new(to_canon_bind_group_layout),
            readback_staging: RefCell::new(None),
            readback_capacity: RefCell::new(0),
            mds_circ,
            mds_diag,
            round_constants,
        }
    }
}

impl MerkleTreeGpuContext {
    fn get_or_make_staging(&self, size: u64) -> Buffer {
        let mut cap = self.readback_capacity.borrow_mut();
        let mut buf_opt = self.readback_staging.borrow_mut();
        let need_new = buf_opt.is_none() || *cap < size;
        if need_new {
            let new_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("merkle-readback-staging"),
                size,
                usage: wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                mapped_at_creation: false,
            });
            *buf_opt = Some(new_buf);
            *cap = size;
        }
        buf_opt.as_ref().unwrap().clone()
    }
}

/// Parameters handed to the Merkle tree kernel for a single layer dispatch.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
struct MerkleTreeKernelArgs {
    cap_len: u32,
    layer: u32,
    src_layer_size: u32,
    dst_layer_size: u32,
    src_offset: u32,
    dst_offset: u32,
    write_to_cap: u32,
}

/// Montgomery helper: convert canonical Goldilocks element (as `u64`) into Montgomery form.
fn to_montgomery_u64(value: u64) -> u64 {
    let res = ((value as u128) * MONTGOMERY_R) % (GOLDILOCKS_MODULUS as u128);
    res as u64
}

fn field_to_montgomery_words<F: RichField>(value: &F) -> [u32; BIGINT_LIMBS] {
    let canonical = value.to_canonical_u64();
    let monty = to_montgomery_u64(canonical);
    [(monty & 0xFFFF_FFFF) as u32, (monty >> 32) as u32]
}

fn field_to_words<F: RichField>(value: &F) -> [u32; BIGINT_LIMBS] {
    let canon = value.to_canonical_u64();
    [(canon & 0xFFFF_FFFF) as u32, (canon >> 32) as u32]
}

fn words_to_field<F: RichField>(words: &[u32; BIGINT_LIMBS]) -> F {
    let canon = (words[1] as u64) << 32 | (words[0] as u64);
    F::from_canonical_u64(canon)
}

fn words_to_hash<F: RichField>(words: &[u32]) -> Result<HashOut<F>> {
    ensure!(
        words.len() == WORDS_PER_DIGEST,
        "expected {} words per digest, got {}",
        WORDS_PER_DIGEST,
        words.len()
    );
    let mut elements = [F::ZERO; NUM_HASH_OUT_ELTS];
    for (i, chunk) in words.chunks(BIGINT_LIMBS).enumerate() {
        let chunk: [u32; BIGINT_LIMBS] = chunk.try_into().unwrap();
        elements[i] = words_to_field(&chunk);
    }
    Ok(HashOut { elements })
}

fn log(msg: &str) {
    #[cfg(not(feature = "gpu_merkle_logging"))]
    let _ = msg;

    #[cfg(target_arch = "wasm32")]
    {
        #[cfg(feature = "gpu_merkle_logging")]
        web_sys::console::log_1(&msg.into());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        println!("{msg}");
    }
}

fn log_lazy<F>(builder: F)
where
    F: FnOnce() -> String,
{
    #[cfg(feature = "gpu_merkle_logging")]
    {
        log(&builder());
    }

    #[cfg(not(feature = "gpu_merkle_logging"))]
    {
        let _ = builder;
    }
}

fn log_queue_submission(label: &str, index: SubmissionIndex) {
    log_lazy(|| format!("📤 Queue submit -> {label} (submission_index={index:?})"));
}

/// Monotonic identifier used to correlate instrumentation logs.
static READBACK_SEQ: AtomicU32 = AtomicU32::new(1);

// ============================================================================
// PROFILING HELPERS
// ============================================================================

/// We need to use the `performance` feature of WASM for profiling. Otherwise when
/// running in a web worker
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance)]
    fn now() -> f64;
}

/// Get high-resolution timestamp in milliseconds
fn now_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        //web_sys::window().unwrap().performance().unwrap().now()
        now()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // For native, use a simple placeholder
        0.0
    }
}

/// Log timing information to console
fn log_timing(label: &str, duration_ms: f64) {
    #[cfg(target_arch = "wasm32")]
    {
        console::log_1(&format!("⏱️  {}: {:.2}ms", label, duration_ms).into());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        println!("⏱️  {}: {:.2}ms", label, duration_ms);
    }
}

/// Log timing information to console
fn log_timing_verbose(label: &str, duration_ms: f64) {
    #[cfg(not(feature = "gpu_merkle_verbose_time_logging"))]
    {
        let _ = label;
        let _ = duration_ms;
    }

    #[cfg(target_arch = "wasm32")]
    {
        #[cfg(feature = "gpu_merkle_verbose_time_logging")]
        console::log_1(&format!("⏱️  {}: {:.2}ms", label, duration_ms).into());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        println!("⏱️  {}: {:.2}ms", label, duration_ms);
    }
}

/// Yield back to the JS event loop to give pending GPU callbacks a chance to fire.
async fn yield_to_event_loop() {
    let promise = Promise::resolve(&JsValue::NULL);
    let _ = JsFuture::from(promise).await;
}

/// Helper that pops a previously-pushed error scope.
async fn pop_error_scope(device: Rc<Device>, label: String) -> Option<wgpu::Error> {
    let result = device.pop_error_scope().await;
    if let Some(ref err) = result {
        log_lazy(|| format!("{label} -> error: {err:?}"));
    } else {
        log_lazy(|| format!("{label} -> no error"));
    }
    result
}

/// Initialize the global WebGPU context. Subsequent calls are no-ops.
pub async fn initialize() -> Result<()> {
    if GPU_CONTEXT.with(|cell| cell.get().is_some()) {
        return Ok(());
    }

    log("Initializing GPU context");

    let inst_desc = wgpu::InstanceDescriptor {
        backends: wgpu::Backends::BROWSER_WEBGPU,
        ..Default::default()
    };
    let instance = wgpu::Instance::new(&inst_desc);

    log("Requesting adapter");

    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        })
        .await
        .expect("failed to obtain WebGPU adapter");
    //.ok_or_else(|| anyhow!("failed to obtain WebGPU adapter"))?;

    log("Requesting device");

    let mut limits = wgpu::Limits::default();
    //limits.max_buffer_size = (1 << 32) - 5;
    //limits.max_storage_buffer_binding_size = (1 << 32) - 5;
    limits.max_buffer_size = 1073741824;
    limits.max_storage_buffer_binding_size = 1073741824;

    let (device, queue) = adapter
        .request_device(
            &wgpu::DeviceDescriptor {
                label: Some("Merkle Tree Device"),
                required_features: wgpu::Features::empty(),
                required_limits: limits,
                memory_hints: wgpu::MemoryHints::MemoryUsage,
                trace: wgpu::Trace::Off,
            },
            //None,
        )
        .await
        .map_err(|err| anyhow!("failed to create WebGPU device: {err}"))?;

    log("Creating bind group layouts");

    let merkle_bind_group_layout = create_merkle_bind_group_layout(&device);
    let merkle_pipeline = create_merkle_pipeline(&device, &merkle_bind_group_layout)?;
    let leaf_bind_group_layout = create_leaf_hash_bind_group_layout(&device);
    let leaf_pipeline = create_leaf_hash_pipeline(&device, &leaf_bind_group_layout)?;
    let transpose_to_mont_bind_group_layout = create_transpose_to_mont_bind_group_layout(&device);
    let transpose_to_mont_pipeline =
        create_transpose_to_mont_pipeline(&device, &transpose_to_mont_bind_group_layout)?;
    let to_canon_bind_group_layout = create_to_canon_bind_group_layout(&device);
    let to_canon_pipeline = create_to_canon_pipeline(&device, &to_canon_bind_group_layout)?;

    let (mds_circ, mds_diag, round_constants) = create_poseidon_constant_buffers::<
        crate::field::goldilocks_field::GoldilocksField,
    >(&device);

    log("Creating Merkle GPU context");

    let context = Rc::new(MerkleTreeGpuContext::new(
        device,
        queue,
        merkle_pipeline,
        merkle_bind_group_layout,
        leaf_pipeline,
        leaf_bind_group_layout,
        transpose_to_mont_pipeline,
        transpose_to_mont_bind_group_layout,
        to_canon_pipeline,
        to_canon_bind_group_layout,
        mds_circ,
        mds_diag,
        round_constants,
    ));

    log("Setting RC cell content");

    GPU_CONTEXT.with(|cell| {
        cell.set(context)
            .map_err(|_| anyhow!("GPU context already initialized"))
    })?;

    console::info_1(&"Merkle GPU context initialized".into());
    Ok(())
}

fn create_merkle_pipeline(
    device: &Device,
    bind_group_layout: &BindGroupLayout,
) -> Result<ComputePipeline> {
    let shader_module =
        device.create_shader_module(wgpu::include_wgsl!("../../shaders/merkle_tree.wgsl"));

    log("creating Merkle tree compute pipeline");
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Merkle Tree Pipeline Layout"),
        bind_group_layouts: &[bind_group_layout],
        push_constant_ranges: &[],
    });

    Ok(
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Merkle Tree Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("processMerkleTreeLayerWithCap"),
            compilation_options: Default::default(),
            cache: None,
        }),
    )
}

fn create_leaf_hash_pipeline(
    device: &Device,
    bind_group_layout: &BindGroupLayout,
) -> Result<ComputePipeline> {
    let shader_module =
        device.create_shader_module(wgpu::include_wgsl!("../../shaders/poseidon1_hash.wgsl"));

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Poseidon Leaf Hash Pipeline Layout"),
        bind_group_layouts: &[bind_group_layout],
        push_constant_ranges: &[],
    });

    Ok(
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Poseidon Leaf Hash Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("poseidon1Hash"),
            compilation_options: Default::default(),
            cache: None,
        }),
    )
}

fn create_transpose_to_mont_pipeline(
    device: &Device,
    bind_group_layout: &BindGroupLayout,
) -> Result<ComputePipeline> {
    let shader_module = device.create_shader_module(wgpu::include_wgsl!(
        "../../shaders/transpose_to_montgomery.wgsl"
    ));

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Buffer Transpose to Montgomery Pipeline Layout"),
        bind_group_layouts: &[bind_group_layout],
        push_constant_ranges: &[],
    });

    Ok(
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Buffer Transpose to Montgomery Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("transposeNaive"),
            compilation_options: Default::default(),
            cache: None,
        }),
    )
}

fn create_to_canon_pipeline(
    device: &Device,
    bind_group_layout: &BindGroupLayout,
) -> Result<ComputePipeline> {
    let shader_module = device.create_shader_module(wgpu::include_wgsl!(
        "../../shaders/buffer_montgomery_to_canonical.wgsl"
    ));

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Buffer Montgomery to Canonical Pipeline Layout"),
        bind_group_layouts: &[bind_group_layout],
        push_constant_ranges: &[],
    });

    Ok(
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Buffer Montgomery to Canonical Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader_module,
            entry_point: Some("bufferToCanonical"),
            compilation_options: Default::default(),
            cache: None,
        }),
    )
}

/// Returns `true` when the WebGPU context is ready for use.
pub fn is_initialized() -> bool {
    GPU_CONTEXT.with(|cell| cell.get().is_some())
}

fn create_merkle_bind_group_layout(device: &Device) -> BindGroupLayout {
    device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Merkle Tree Bind Group Layout"),
        entries: &[
            // 0: input hashed leaves
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            // 1: nodes buffer
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            // 2: cap buffer
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            // 3: per-layer uniforms
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        std::mem::size_of::<MerkleTreeKernelArgs>() as u64
                    ),
                },
                count: None,
            },
            // 4: Poseidon MDS circulant
            wgpu::BindGroupLayoutEntry {
                binding: 4,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (POSEIDON_WIDTH * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
            // 5: Poseidon MDS diagonal
            wgpu::BindGroupLayoutEntry {
                binding: 5,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (POSEIDON_WIDTH * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
            // 6: round constants
            wgpu::BindGroupLayoutEntry {
                binding: 6,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (ROUND_CONSTANT_COUNT * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
        ],
    })
}

fn create_leaf_hash_bind_group_layout(device: &Device) -> BindGroupLayout {
    device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Poseidon Leaf Hash Bind Group Layout"),
        entries: &[
            // 0: output digests
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(BYTES_PER_DIGEST as u64),
                },
                count: None,
            },
            // 1: transposed input elements
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            // 2: number of leaves
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<i32>() as u64),
                },
                count: None,
            },
            // 3: elements per leaf
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<i32>() as u64),
                },
                count: None,
            },
            // 4: Poseidon MDS circulant
            wgpu::BindGroupLayoutEntry {
                binding: 4,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (POSEIDON_WIDTH * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
            // 5: Poseidon MDS diagonal
            wgpu::BindGroupLayoutEntry {
                binding: 5,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (POSEIDON_WIDTH * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
            // 6: round constants
            wgpu::BindGroupLayoutEntry {
                binding: 6,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(
                        (ROUND_CONSTANT_COUNT * BIGINT_LIMBS * std::mem::size_of::<u32>()) as u64,
                    ),
                },
                count: None,
            },
        ],
    })
}

fn create_transpose_to_mont_bind_group_layout(device: &Device) -> BindGroupLayout {
    device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Buffer Transpose to Montgomery Bind Group Layout"),
        entries: &[
            // 0: output buffer
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(BYTES_PER_BIGINT as u64),
                },
                count: None,
            },
            // 1: input buffer to transpose & convert
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(BYTES_PER_BIGINT as u64),
                },
                count: None,
            },
            // 2: number of leaves
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<u32>() as u64),
                },
                count: None,
            },
            // 2: elements per leaf
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<u32>() as u64),
                },
                count: None,
            },
        ],
    })
}

fn create_to_canon_bind_group_layout(device: &Device) -> BindGroupLayout {
    device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Buffer Montgomery to Canonical Bind Group Layout"),
        entries: &[
            // 0: input & output buffer to convert
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(BYTES_PER_BIGINT as u64),
                },
                count: None,
            },
            // 1: number of elements in the buffer
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: NonZeroU64::new(std::mem::size_of::<i32>() as u64),
                },
                count: None,
            },
        ],
    })
}

fn create_poseidon_constant_buffers<F: RichField + Poseidon>(
    device: &Device,
) -> (Buffer, Buffer, Buffer) {
    let mut mds_circ_words = Vec::with_capacity(POSEIDON_WIDTH * BIGINT_LIMBS);
    for &value in F::MDS_MATRIX_CIRC.iter().take(POSEIDON_WIDTH) {
        let field = F::from_canonical_u64(value);
        mds_circ_words.extend_from_slice(&field_to_montgomery_words(&field));
    }

    let mut mds_diag_words = Vec::with_capacity(POSEIDON_WIDTH * BIGINT_LIMBS);
    for &value in F::MDS_MATRIX_DIAG.iter().take(POSEIDON_WIDTH) {
        let field = F::from_canonical_u64(value);
        mds_diag_words.extend_from_slice(&field_to_montgomery_words(&field));
    }

    let mut rc_words = Vec::with_capacity(ROUND_CONSTANT_COUNT * BIGINT_LIMBS);
    for &value in poseidon::ALL_ROUND_CONSTANTS
        .iter()
        .take(ROUND_CONSTANT_COUNT)
    {
        let field = F::from_canonical_u64(value);
        rc_words.extend_from_slice(&field_to_montgomery_words(&field));
    }

    let mds_circ = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("Poseidon MDS (circ)"),
        contents: bytemuck::cast_slice(&mds_circ_words),
        usage: wgpu::BufferUsages::STORAGE,
    });

    let mds_diag = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("Poseidon MDS (diag)"),
        contents: bytemuck::cast_slice(&mds_diag_words),
        usage: wgpu::BufferUsages::STORAGE,
    });

    let round_constants = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("Poseidon round constants"),
        contents: bytemuck::cast_slice(&rc_words),
        usage: wgpu::BufferUsages::STORAGE,
    });

    (mds_circ, mds_diag, round_constants)
}

fn host_layer_size(input_size: usize, layer: usize) -> usize {
    if layer == 0 {
        return input_size;
    }
    let mut size = input_size / 2;
    for _ in 1..layer {
        size = (size + 1) / 2;
    }
    size
}

fn host_layer_offset(input_size: usize, layer: usize) -> usize {
    let mut offset = 0;
    let mut size = input_size / 2;
    for _ in 1..layer {
        offset += size;
        size = (size + 1) / 2;
    }
    offset
}

#[derive(Debug)]
struct MerkleBuffers {
    input: Buffer,
    nodes: Buffer,
    cap: Buffer,
}

#[derive(Debug)]
struct QueueCompletion {
    receiver: oneshot::Receiver<()>,
}

impl QueueCompletion {
    fn new(queue: Rc<Queue>) -> Self {
        let (sender, receiver) = oneshot::channel();
        queue.on_submitted_work_done(move || {
            log("wait_for_queue -> on_submitted_work_done invoked");
            let _ = sender.send(());
        });
        Self { receiver }
    }

    async fn wait(self) -> Result<()> {
        self.receiver
            .await
            .map_err(|_| anyhow!("queue completion receiver dropped"))
    }
}

#[derive(Debug)]
enum MerkleGpuJobState {
    Deferred {
        context: Rc<MerkleTreeGpuContext>,
        buffers: MerkleBuffers,
        total_nodes: usize,
        cap_len: usize,
        num_leaves: usize,
        cap_height: usize,
        num_layers_to_cap: usize,
        queue_completion: Option<QueueCompletion>,
    },
}

#[derive(Debug)]
pub struct MerkleGpuJob<F: RichField> {
    state: MerkleGpuJobState,
    _marker: PhantomData<F>,
}

impl<F> MerkleGpuJob<F>
where
    F: RichField + Poseidon + 'static,
{
    fn deferred(
        context: Rc<MerkleTreeGpuContext>,
        buffers: MerkleBuffers,
        total_nodes: usize,
        cap_len: usize,
        num_leaves: usize,
        cap_height: usize,
        num_layers_to_cap: usize,
        queue_completion: Option<QueueCompletion>,
    ) -> Self {
        Self {
            state: MerkleGpuJobState::Deferred {
                context,
                buffers,
                total_nodes,
                cap_len,
                num_leaves,
                cap_height,
                num_layers_to_cap,
                queue_completion,
            },
            _marker: PhantomData,
        }
    }

    async fn finish(self) -> Result<GpuMerkleOutput<F>> {
        match self.state {
            MerkleGpuJobState::Deferred {
                context,
                buffers,
                total_nodes,
                cap_len,
                num_leaves,
                cap_height,
                num_layers_to_cap,
                queue_completion,
            } => {
                log("=== PHASE 4: GPU Completion & Readback ===");
                log(if queue_completion.is_some() {
                    "wait_for_queue will await queued completion callback"
                } else {
                    "wait_for_queue has no completion callback recorded"
                });
                let readback_start = now_ms();

                // Wait for GPU to finish
                let wait_start = now_ms();
                wait_for_queue(queue_completion).await?;
                log_timing("⚡ GPU execution (wait_for_queue)", now_ms() - wait_start);

                let mut sections = Vec::with_capacity(3);
                sections.push(HashSection {
                    label: "Leaf",
                    buffer: &buffers.input,
                    word_len: num_leaves * WORDS_PER_DIGEST,
                });
                if total_nodes > 0 {
                    sections.push(HashSection {
                        label: "Node",
                        buffer: &buffers.nodes,
                        word_len: total_nodes * WORDS_PER_DIGEST,
                    });
                }
                sections.push(HashSection {
                    label: "Cap",
                    buffer: &buffers.cap,
                    word_len: cap_len * WORDS_PER_DIGEST,
                });
                let section_results = read_hash_sections::<F>(&context, &sections).await?;
                debug_assert_eq!(section_results.len(), sections.len());
                let mut section_iter = section_results.into_iter();

                let leaf_result = section_iter
                    .next()
                    .expect("leaf section missing from combined readback");
                log_timing_verbose("Leaf hash readback", leaf_result.readback_ms);
                log_timing_verbose("Leaf canonical decode", leaf_result.convert_ms);
                let leaf_hashes = leaf_result.hashes;

                let (node_hashes, cap_result) = if total_nodes > 0 {
                    let node_result = section_iter
                        .next()
                        .expect("node section missing from combined readback");
                    log_timing_verbose("Node hash readback", node_result.readback_ms);
                    log_timing_verbose("Node canonical decode", node_result.convert_ms);
                    let cap_result = section_iter
                        .next()
                        .expect("cap section missing from combined readback");
                    (node_result.hashes, cap_result)
                } else {
                    let cap_result = section_iter
                        .next()
                        .expect("cap section missing from combined readback");
                    (Vec::new(), cap_result)
                };
                debug_assert!(section_iter.next().is_none());
                log_timing_verbose("Cap readback", cap_result.readback_ms);
                log_timing_verbose("Cap canonical decode", cap_result.convert_ms);
                let cap_hashes = cap_result.hashes;

                // CPU post-processing: reconstruct digest tree
                log("=== PHASE 5: CPU Post-processing ===");
                let postprocess_start = now_ms();

                let num_digests = 2 * (num_leaves - (1 << cap_height));
                let digests = if num_digests > 0 {
                    let mut digests = vec![HashOut::<F>::ZERO; num_digests];
                    let accessor = LayerAccessor::new(
                        &leaf_hashes,
                        &node_hashes,
                        &cap_hashes,
                        num_leaves,
                        num_layers_to_cap,
                    );
                    let subtree_digests_len = num_digests >> cap_height;
                    let subtree_leaves_len = num_leaves >> cap_height;

                    log("Subtree business");
                    for (subtree_idx, subtree_buf) in
                        digests.chunks_mut(subtree_digests_len).enumerate()
                    {
                        let leaf_offset = subtree_idx * subtree_leaves_len;
                        write_subtree_chunk_from_gpu(
                            subtree_buf,
                            &accessor,
                            leaf_offset,
                            subtree_leaves_len,
                        );
                        debug_assert_eq!(
                            accessor.node(accessor.cap_layer(), subtree_idx),
                            &cap_hashes[subtree_idx]
                        );
                    }

                    digests
                } else {
                    Vec::new()
                };

                log_timing_verbose("Digest tree reconstruction", now_ms() - postprocess_start);

                log_timing_verbose(
                    "📥 TOTAL READBACK + POST-PROCESSING",
                    now_ms() - readback_start,
                );

                Ok(GpuMerkleOutput {
                    digests,
                    cap: cap_hashes,
                })
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub async fn await_async(self) -> Result<GpuMerkleOutput<F>> {
        let start = now_ms();
        let result = self.finish().await;
        log_timing("🏁 TOTAL await_async TIME", now_ms() - start);
        result
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn wait(self) -> Result<GpuMerkleOutput<F>> {
        pollster::block_on(self.finish())
    }
}

fn create_buffers(
    ctx: &MerkleTreeGpuContext,
    input: Buffer,
    total_internal_nodes: usize,
    cap_len: usize,
) -> MerkleBuffers {
    let nodes = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("merkle-nodes"),
        size: (total_internal_nodes * BYTES_PER_DIGEST) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let cap = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("merkle-cap"),
        size: (cap_len * BYTES_PER_DIGEST) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    MerkleBuffers { input, nodes, cap }
}

async fn wait_for_queue(queue_completion: Option<QueueCompletion>) -> Result<()> {
    match queue_completion {
        Some(completion) => {
            log("wait_for_queue -> awaiting queue completion callback");
            completion.wait().await?;
            log("wait_for_queue -> completion callback resolved");
            Ok(())
        }
        None => {
            log("wait_for_queue -> skipped (no submissions recorded)");
            Ok(())
        }
    }
}

struct HashSection<'a> {
    label: &'static str,
    buffer: &'a Buffer,
    word_len: usize,
}

struct HashSectionResult<F: RichField> {
    hashes: Vec<HashOut<F>>,
    readback_ms: f64,
    convert_ms: f64,
}

async fn read_hash_sections<F: RichField>(
    context: &MerkleTreeGpuContext,
    sections: &[HashSection<'_>],
) -> Result<Vec<HashSectionResult<F>>> {
    if sections.is_empty() {
        return Ok(Vec::new());
    }

    let total_words: usize = sections.iter().map(|section| section.word_len).sum();
    let total_bytes: u64 = sections
        .iter()
        .map(|section| (section.word_len * std::mem::size_of::<u32>()) as u64)
        .sum();
    let staging = context.get_or_make_staging(total_bytes);

    context
        .device
        .push_error_scope(wgpu::ErrorFilter::Validation);

    let mut encoder = context
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("merkle-combined-readback"),
        });
    let mut offsets_words = Vec::with_capacity(sections.len());
    let mut offset_bytes = 0u64;
    for section in sections {
        let size_bytes = (section.word_len * std::mem::size_of::<u32>()) as u64;
        encoder.copy_buffer_to_buffer(section.buffer, 0, &staging, offset_bytes, size_bytes);
        offsets_words.push((offset_bytes / std::mem::size_of::<u32>() as u64) as usize);
        offset_bytes += size_bytes;
    }
    let submission_index = context.queue.submit(Some(encoder.finish()));
    log_queue_submission("combined_readback_copy", submission_index);

    let slice = staging.slice(0..total_bytes);
    let (map_tx, map_rx) = oneshot::channel();
    let readback_id = READBACK_SEQ.fetch_add(1, Ordering::Relaxed);
    let label = format!("combined_readback[{readback_id}]");
    log_lazy(|| format!("{label} map_async registering"));
    slice.map_async(wgpu::MapMode::Read, move |res| {
        let _ = map_tx.send(res);
    });

    log_lazy(|| format!("{label} awaiting map_async completion"));
    let copy_start = now_ms();
    map_rx
        .await
        .map_err(|_| anyhow!("{label} map_async callback dropped"))?
        .map_err(|err| anyhow!("{label} map_async error: {err:?}"))?;
    let copy_elapsed = now_ms() - copy_start;

    if let Some(err) =
        pop_error_scope(context.device.clone(), format!("{label} validation scope")).await
    {
        return Err(anyhow!("validation error during readback: {err:?}"));
    }

    let data = slice.get_mapped_range();
    let words_slice: &[u32] = bytemuck::cast_slice::<u8, u32>(&data);
    let total_words_f = (total_words.max(1)) as f64;
    let mut results = Vec::with_capacity(sections.len());
    for (idx, section) in sections.iter().enumerate() {
        let start = offsets_words[idx];
        let end = start + section.word_len;
        debug_assert!(
            end <= words_slice.len(),
            "{label} mapped words shorter than expected for {} section",
            section.label
        );
        let convert_start = now_ms();
        let hashes = words_slice[start..end]
            .chunks(WORDS_PER_DIGEST)
            .map(words_to_hash::<F>)
            .collect::<Result<Vec<_>>>()?;
        let convert_ms = now_ms() - convert_start;
        let readback_ms = copy_elapsed * (section.word_len as f64) / total_words_f;
        results.push(HashSectionResult {
            hashes,
            readback_ms,
            convert_ms,
        });
    }
    drop(data);
    staging.unmap();
    yield_to_event_loop().await;

    Ok(results)
}

fn send_chunk_data<F: RichField>(ctx: &MerkleTreeGpuContext, leaves: &[Vec<F>]) -> Buffer {
    //Result<(Vec<u32>, usize)> {
    let num_leaves = leaves.len();
    let elems_per_leaf = leaves[0].len();

    const CHUNK_SIZE: usize = 1000;

    let size = (num_leaves * elems_per_leaf * 2 * core::mem::size_of::<u32>()) as u64;
    let dst = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("merkle-send-chunks"),
        size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let mut i = 0;
    while i < num_leaves {
        let start = i;
        let upto = (num_leaves - i).min(CHUNK_SIZE);
        let elems_this_chunk = upto * elems_per_leaf;

        let offset_bytes = (start as u64) * (elems_per_leaf as u64) * 8;
        let size_bytes = (elems_this_chunk as u64) * 8;

        if let Some(mut view) =
            ctx.queue
                .write_buffer_with(&dst, offset_bytes, size_bytes.try_into().unwrap())
        {
            // SAFELY reinterpret &mut [u8] as &mut [u32] if alignment allows.
            // align_to_mut() handles potential misalignment without UB.
            let (head, out_u32, tail) = unsafe { view.align_to_mut::<u32>() };
            debug_assert!(
                head.is_empty() && tail.is_empty(),
                "staging view not u32-aligned"
            );

            // We expect exactly 2 u32 words per element:
            debug_assert_eq!(out_u32.len(), 2 * elems_this_chunk);

            // Fill directly from field_to_words:
            let mut idx = 0;
            for leaf in &leaves[start..start + upto] {
                for &val in &leaf[..elems_per_leaf] {
                    let [lo, hi] = field_to_words(&val);
                    out_u32[idx] = lo;
                    out_u32[idx + 1] = hi;
                    idx += 2;
                }
            }
            // Dropping `view` schedules the copy; it transfers on the next queue.submit().
        } else {
            // Fallback: extremely unlikely unless validation fails.
            // You could bail or fall back to a reusable Vec<u32> + write_buffer here.
            panic!("write_buffer_with failed validation");
        }

        i += upto;
    }

    dst
}

/// Computes the required workgroup sizes in x and y to produce `num` threads.
/// We assume a workgroup size of 64!
fn compute_workgroups(num: usize) -> (u32, u32) {
    const WORKGROUP_SIZE: usize = 64;
    const MAX_DIM: usize = 1 << 16; // maximum dimension of a workgroup
                                    // we divide `maxDim` by 2 so that the max X dim is 2^15 = 32768
    let num_blocks = (num + WORKGROUP_SIZE - 1) / WORKGROUP_SIZE;

    let workgroups_y = if num_blocks >= MAX_DIM {
        num_blocks / (MAX_DIM / 2)
    } else {
        1
    };
    let workgroups_x = (num_blocks + workgroups_y - 1) / workgroups_y;

    (workgroups_x as u32, workgroups_y as u32)
}

fn hash_leaves_gpu(
    ctx: &MerkleTreeGpuContext,
    leaf_buf: Buffer,
    num_leaves: usize,
    elements_per_leaf: usize,
) -> Result<(Buffer, SubmissionIndex)> {
    // Time buffer creation
    let buffer_start = now_ms();

    let output_buffer = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("poseidon-leaf-output"),
        size: (num_leaves * BYTES_PER_DIGEST) as u64,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let num_leaves_i32 = num_leaves as i32;
    let num_buffer = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("poseidon-leaf-count"),
            contents: bytemuck::bytes_of(&num_leaves_i32),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

    let elements_per_leaf_i32 = elements_per_leaf as i32;
    let elements_buffer = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("poseidon-leaf-width"),
            contents: bytemuck::bytes_of(&elements_per_leaf_i32),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

    let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("poseidon-leaf-bind-group"),
        layout: &ctx.leaf_bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: output_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: leaf_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: num_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: elements_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 4,
                resource: ctx.mds_circ.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 5,
                resource: ctx.mds_diag.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 6,
                resource: ctx.round_constants.as_entire_binding(),
            },
        ],
    });
    log_timing_verbose(
        "  Leaf buffer creation + bind group",
        now_ms() - buffer_start,
    );

    // Time dispatch
    let dispatch_start = now_ms();
    let (workgroups_x, workgroups_y) = compute_workgroups(num_leaves);

    let mut encoder = ctx
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("poseidon-leaf-encoder"),
        });

    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("poseidon-leaf-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&ctx.leaf_pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(workgroups_x, workgroups_y, 1);
    }

    let submission_index = ctx.queue.submit(Some(encoder.finish()));
    log_queue_submission("hash_leaves_gpu", submission_index.clone());
    log_timing_verbose("  Leaf dispatch", now_ms() - dispatch_start);

    Ok((output_buffer, submission_index))
}

fn transpose_to_mont_gpu(
    ctx: &MerkleTreeGpuContext,
    input_buf: &Buffer,
    num_leaves: usize,
    elems_per_leaf: usize,
) -> Result<(Buffer, SubmissionIndex)> {
    let size = input_buf.size();
    let output_buf = ctx.device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("transpose-to-mont-output"),
        size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        //usage: wgpu::BufferUsage::COPY_DST, // don'
        mapped_at_creation: false,
    });

    let num_u32 = num_leaves as u32;
    let num_buf = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("transpose-buf-num-leaves"),
            contents: bytemuck::bytes_of(&num_u32),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });
    let elems_per_leaf_u32 = elems_per_leaf as u32;
    let elems_per_leaf_buf = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("transpose-buf-elems-per-leaf"),
            contents: bytemuck::bytes_of(&elems_per_leaf_u32),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

    let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("to-montgomery-bind-group"),
        layout: &ctx.transpose_to_mont_bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: output_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: input_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: num_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: elems_per_leaf_buf.as_entire_binding(),
            },
        ],
    });
    // Time dispatch
    let dispatch_start = now_ms();

    let bx = 16;
    let by = 16;
    let workgroups_x = (elems_per_leaf + bx - 1) / bx; // across columns;
    let workgroups_y = (num_leaves + by - 1) / by; // across rows;

    log::info!(
        "Starting workgroups in (x, y) : ({}, {})",
        workgroups_x,
        workgroups_y
    );

    let mut encoder = ctx
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("transpose-to-mont-encoder"),
        });

    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("transpose-to-mont-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&ctx.transpose_to_mont_pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        //pass.dispatch_workgroups(workgroups_x, 1, 1);
        pass.dispatch_workgroups(workgroups_x as u32, workgroups_y as u32, 1);
    }

    let submission_index = ctx.queue.submit(Some(encoder.finish()));
    log_queue_submission("canonical_to_montgomery_gpu", submission_index.clone());
    log_timing_verbose("  Canon->Mont dispatch", now_ms() - dispatch_start);

    Ok((output_buf, submission_index))
}

/// Converts the input buffer from Montgomery representation into canonical representation
/// to put it back into the form Plonky2 expects.
/// `num` is the number of field elements in the buffer.
fn montgomery_to_canonical_gpu(
    ctx: &MerkleTreeGpuContext,
    buf: &Buffer,
    num: u32,
) -> Option<SubmissionIndex> {
    if num == 0 {
        log("montgomery_to_canonical_gpu skipped (num == 0)");
        return None;
    }

    // Time buffer creation
    let buffer_start = now_ms();

    let num_i32 = num as i32;
    let num_buffer = ctx
        .device
        .create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("buf-elems-count"),
            contents: bytemuck::bytes_of(&num_i32),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

    let bind_group = ctx.device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("to-montgomery-bind-group"),
        layout: &ctx.to_canon_bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: num_buffer.as_entire_binding(),
            },
        ],
    });
    log_timing_verbose(
        "  Mont->Canon buffer creation + bind group",
        now_ms() - buffer_start,
    );

    // Time dispatch
    let dispatch_start = now_ms();

    let (workgroups_x, workgroups_y) = compute_workgroups(num as usize);

    let mut encoder = ctx
        .device
        .create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("buf-mont-canon-encoder"),
        });

    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("buf-mont-canon-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&ctx.to_canon_pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(workgroups_x, workgroups_y, 1);
    }

    let submission_index = ctx.queue.submit(Some(encoder.finish()));
    log_queue_submission("montgomery_to_canonical_gpu", submission_index.clone());
    log_timing_verbose("  Mont->Canon dispatch", now_ms() - dispatch_start);

    Some(submission_index)
}

fn leaf_info<F>(leaves: &[Vec<F>]) -> (usize, usize)
where
    F: RichField + Poseidon,
{
    // TODO: Transpose the leaf nodes here
    let num_leaves = leaves.len();
    let elements_per_leaf = leaves[0].len();
    (num_leaves, elements_per_leaf)
}

/// Run the GPU Merkle tree pipeline, returning a job that resolves once GPU buffers are ready.
pub fn build_merkle_tree<F>(
    ctx: Rc<MerkleTreeGpuContext>,
    leaves: &[Vec<F>],
    cap_height: usize,
) -> Result<MerkleGpuJob<F>>
where
    F: RichField + Poseidon,
{
    let total_start = now_ms();

    let ctx_ref = ctx.as_ref();
    let mut saw_submission = false;

    let (num_leaves, elements_per_leaf) = leaf_info(leaves);
    let config_msg = format!(
        "GPU Merkle config -> leaves: {num_leaves}, elements_per_leaf: {elements_per_leaf}, cap_height: {cap_height}"
    );
    log(&config_msg);
    ensure!(num_leaves > 0, "Merkle tree requires at least one leaf");
    ensure!(
        num_leaves <= i32::MAX as usize,
        "Merkle GPU hashing expects leaf count to fit in i32, got {num_leaves}"
    );
    ensure!(
        leaves.iter().all(|leaf| leaf.len() == elements_per_leaf),
        "GPU Poseidon hashing requires leaves of uniform length"
    );
    ensure!(
        num_leaves.is_power_of_two(),
        "GPU Merkle currently expects a power-of-two leaf count"
    );

    let depth = num_leaves.trailing_zeros() as usize;
    ensure!(
        cap_height <= depth,
        "cap_height {cap_height} exceeds tree depth {depth}"
    );
    let depth_msg = format!("GPU Merkle depth -> depth: {depth}");
    log(&depth_msg);

    let num_layers_to_root = depth;
    let num_layers_to_cap = num_layers_to_root - cap_height;
    let cap_len = 1usize << cap_height;

    let total_nodes: usize = (1..num_layers_to_cap)
        .map(|layer| host_layer_size(num_leaves, layer))
        .sum();
    let sizing_msg = format!(
        "GPU Merkle sizing -> num_layers_to_root: {num_layers_to_root}, num_layers_to_cap: {num_layers_to_cap}, cap_len: {cap_len}, total_internal_nodes: {total_nodes}"
    );
    log(&sizing_msg);

    if total_nodes == 0 {
        let fallback_msg = format!(
            "GPU Merkle fallback: total_internal_nodes is zero (leaves={num_leaves}, cap_height={cap_height}, num_layers_to_cap={num_layers_to_cap}). Falling back to CPU."
        );
        log(&fallback_msg);
        return Err(anyhow!(
            "GPU Merkle skipped: total_internal_nodes == 0 for leaves={num_leaves}, cap_height={cap_height}"
        ));
    }

    // Time data conversion
    //let convert_start = now_ms();
    ensure!(
        elements_per_leaf > 0,
        "GPU Poseidon hashing received empty leaves"
    );
    ensure!(
        elements_per_leaf <= i32::MAX as usize,
        "elements_per_leaf must fit in i32, got {elements_per_leaf}"
    );
    //log_timing("  Leaf data transpose", now_ms() - convert_start);

    // TODO: Perform single canonical -> Montgomery representation pass on inputs

    // 4. Send data in chunks to the GPU and then transpose + Montgomery convert on GPU
    let chunk_send_start = now_ms();
    let input_buf = send_chunk_data(&ctx, leaves);
    let chunk_send_stop = now_ms();
    log_timing(
        "    Sending data in chunks to GPU",
        chunk_send_stop - chunk_send_start,
    );

    // Convert canonical words into Montgomery form via the GPU pipeline
    let canon_to_mont_start = now_ms();
    let (input_buffer, _submission_index) =
        //canonical_to_montgomery_gpu(&ctx, &canonical_words, num_leaves * elements_per_leaf)?;
        transpose_to_mont_gpu(&ctx, &input_buf, num_leaves, elements_per_leaf)?;
    if !saw_submission {
        saw_submission = true;
    }
    log_timing(
        "  Leaf data Canonical -> Montgomery conversion",
        now_ms() - canon_to_mont_start,
    );
    // Release the large canonical word buffer before launching downstream GPU work.
    //drop(canonical_words);

    // TODO: After main Merkle tree kernel calls: single Montgomery -> canonical pass for all digsts / nodes

    // PHASE 1: Leaf hashing setup and dispatch
    log("=== PHASE 1: Leaf Hashing ===");
    let leaf_start = now_ms();
    log("launching GPU Poseidon hashing");
    let (leaf_buffer, _submission_index) =
        hash_leaves_gpu(ctx_ref, input_buffer, num_leaves, elements_per_leaf)?;
    if !saw_submission {
        saw_submission = true;
    }
    log("queued GPU Poseidon hashing");
    log_timing_verbose("Leaf hash setup + dispatch", now_ms() - leaf_start);

    // PHASE 2: Buffer allocation
    log("=== PHASE 2: Buffer Creation ===");

    let buffer_start = now_ms();
    let buffers = create_buffers(ctx_ref, leaf_buffer, total_nodes, cap_len);
    log_timing_verbose("Buffer allocation", now_ms() - buffer_start);

    // PHASE 3: Layer processing
    log_lazy(|| format!(
        "=== PHASE 3: Layer Processing ({} layers) ===",
        num_layers_to_cap
    ));
    let layer_setup_start = now_ms();

    for layer in 0..num_layers_to_cap {
        let layer_start = now_ms();

        log_lazy(|| format!("layer: {}", layer));
        let src_layer_size = host_layer_size(num_leaves, layer);
        let dst_layer_size = host_layer_size(num_leaves, layer + 1);
        let src_offset = if layer == 0 {
            0
        } else {
            host_layer_offset(num_leaves, layer)
        };
        let dst_offset = if layer + 1 < num_layers_to_cap {
            host_layer_offset(num_leaves, layer + 1)
        } else {
            0
        };
        let write_to_cap = (layer + 1) == num_layers_to_cap;
        log_lazy(|| {
            format!(
                "  layer sizes -> layer: {layer}, src_layer_size: {src_layer_size}, dst_layer_size: {dst_layer_size}, src_offset: {src_offset}, dst_offset: {dst_offset}, write_to_cap: {write_to_cap}"
            )
        });

        let args = MerkleTreeKernelArgs {
            cap_len: cap_len as u32,
            layer: layer as u32,
            src_layer_size: src_layer_size as u32,
            dst_layer_size: dst_layer_size as u32,
            src_offset: src_offset as u32,
            dst_offset: dst_offset as u32,
            write_to_cap: write_to_cap as u32,
        };

        // Time bind group creation
        let bind_start = now_ms();
        let args_buffer = ctx_ref
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some(&format!("merkle-layer-args-{layer}")),
                contents: bytemuck::bytes_of(&args),
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            });

        let bind_group = ctx_ref
            .device
            .create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(&format!("merkle-layer-bind-group-{layer}")),
                layout: &ctx_ref.merkle_bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: buffers.input.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: buffers.nodes.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: buffers.cap.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: args_buffer.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 4,
                        resource: ctx_ref.mds_circ.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 5,
                        resource: ctx_ref.mds_diag.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 6,
                        resource: ctx_ref.round_constants.as_entire_binding(),
                    },
                ],
            });
        let bind_time = now_ms() - bind_start;

        // Time encoder creation and dispatch
        let encode_start = now_ms();
        let mut encoder = ctx_ref
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some(&format!("merkle-layer-{layer}-encoder")),
            });

        log("execute layer");

        let (workgroups_x, workgroups_y) = compute_workgroups(dst_layer_size);
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some(&format!("merkle-layer-{layer}-pass")),
                timestamp_writes: None,
            });
            pass.set_pipeline(&ctx_ref.merkle_pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            pass.dispatch_workgroups(workgroups_x, workgroups_y, 1);
        }
        let encode_time = now_ms() - encode_start;

        // Time submission (should be fast)
        let submit_start = now_ms();
        let submission_index = ctx_ref.queue.submit(Some(encoder.finish()));
        log_lazy(|| {
            format!(
                "📤 Queue submit -> merkle_layer_{layer} (submission_index={submission_index:?})"
            )
        });
        if !saw_submission {
            saw_submission = true;
        }
        let submit_time = now_ms() - submit_start;

        let layer_time = now_ms() - layer_start;
        log_lazy(|| {
            format!(
                "  Layer {}: total={:.2}ms (bind={:.2}ms, encode={:.2}ms, submit={:.2}ms)",
                layer, layer_time, bind_time, encode_time, submit_time
            )
        });
    }

    // Convert input buffer (leaf nodes) from Montgomery into canonical repr
    if montgomery_to_canonical_gpu(
        ctx_ref,
        &buffers.input,
        (num_leaves * NUM_HASH_OUT_ELTS) as u32,
    )
    .is_some()
    {
        if !saw_submission {
            saw_submission = true;
        }
    }
    if montgomery_to_canonical_gpu(
        ctx_ref,
        &buffers.nodes,
        (total_nodes * NUM_HASH_OUT_ELTS) as u32,
    )
    .is_some()
    {
        if !saw_submission {
            saw_submission = true;
        }
    }

    let total_layer_time = now_ms() - layer_setup_start;
    log_timing_verbose("Total layer setup + dispatch", total_layer_time);

    log("queued GPU Merkle buffers");

    let total_setup_time = now_ms() - total_start;
    log_timing(
        "🔧 TOTAL SETUP TIME (everything before GPU wait)",
        total_setup_time,
    );

    if !saw_submission {
        log("Merkle GPU pipeline recorded no queue submissions before wait (unexpected)");
    }

    let queue_completion = if saw_submission {
        Some(QueueCompletion::new(ctx.queue.clone()))
    } else {
        None
    };

    Ok(MerkleGpuJob::deferred(
        ctx,
        buffers,
        total_nodes,
        cap_len,
        num_leaves,
        cap_height,
        num_layers_to_cap,
        queue_completion,
    ))
}

struct SubtreeFrame {
    start: usize,
    len: usize,
    leaf_offset: usize,
    leaves_len: usize,
    layer_index: usize,
}

fn write_subtree_chunk_from_gpu<F: RichField>(
    chunk: &mut [HashOut<F>],
    accessor: &LayerAccessor<'_, F>,
    leaf_offset: usize,
    subtree_leaves_len: usize,
) {
    if chunk.is_empty() {
        debug_assert_eq!(subtree_leaves_len, 1);
        return;
    }

    let mut stack = vec![SubtreeFrame {
        start: 0,
        len: chunk.len(),
        leaf_offset,
        leaves_len: subtree_leaves_len,
        layer_index: accessor.cap_layer(),
    }];

    while let Some(frame) = stack.pop() {
        if frame.leaves_len <= 1 || frame.len == 0 {
            continue;
        }
        debug_assert!(frame.layer_index > 0);
        debug_assert_eq!(frame.len, 2 * (frame.leaves_len - 1));

        let half_leaves = frame.leaves_len / 2;
        let chunk_half = frame.len / 2;
        let left_slot = frame.start + chunk_half - 1;
        let right_slot = frame.start + chunk_half;
        let child_layer = frame.layer_index - 1;

        let left_node_idx = frame.leaf_offset >> child_layer;
        let right_leaf_offset = frame.leaf_offset + half_leaves;
        let right_node_idx = right_leaf_offset >> child_layer;

        chunk[left_slot] = accessor.node(child_layer, left_node_idx).clone();
        chunk[right_slot] = accessor.node(child_layer, right_node_idx).clone();

        let subtree_len = chunk_half - 1;
        if subtree_len > 0 {
            stack.push(SubtreeFrame {
                start: right_slot + 1,
                len: subtree_len,
                leaf_offset: right_leaf_offset,
                leaves_len: half_leaves,
                layer_index: child_layer,
            });
            stack.push(SubtreeFrame {
                start: frame.start,
                len: subtree_len,
                leaf_offset: frame.leaf_offset,
                leaves_len: half_leaves,
                layer_index: child_layer,
            });
        }
    }
}

struct LayerAccessor<'a, F: RichField> {
    leaf_hashes: &'a [HashOut<F>],
    node_hashes: &'a [HashOut<F>],
    cap_hashes: &'a [HashOut<F>],
    layer_starts: Vec<usize>,
    num_layers_to_cap: usize,
}

impl<'a, F: RichField> LayerAccessor<'a, F> {
    fn new(
        leaf_hashes: &'a [HashOut<F>],
        node_hashes: &'a [HashOut<F>],
        cap_hashes: &'a [HashOut<F>],
        num_leaves: usize,
        num_layers_to_cap: usize,
    ) -> Self {
        let mut layer_starts = vec![0usize; num_layers_to_cap];
        let mut acc = 0;
        for layer in 1..num_layers_to_cap {
            layer_starts[layer] = acc;
            acc += host_layer_size(num_leaves, layer);
        }
        debug_assert_eq!(acc, node_hashes.len());
        Self {
            leaf_hashes,
            node_hashes,
            cap_hashes,
            layer_starts,
            num_layers_to_cap,
        }
    }

    fn node(&self, layer: usize, node_idx: usize) -> &HashOut<F> {
        match layer {
            0 => &self.leaf_hashes[node_idx],
            l if l < self.num_layers_to_cap => {
                let start = self.layer_starts[l];
                &self.node_hashes[start + node_idx]
            }
            l if l == self.num_layers_to_cap => &self.cap_hashes[node_idx],
            _ => panic!("layer {layer} out of bounds"),
        }
    }

    fn cap_layer(&self) -> usize {
        self.num_layers_to_cap
    }
}

/// Attempt to build the Merkle tree using the GPU path. Returns `None` if the GPU context has not
/// been initialised.
pub fn try_build_merkle_tree<F>(
    leaves: &[Vec<F>],
    cap_height: usize,
) -> Option<Result<MerkleGpuJob<F>>>
where
    F: RichField + Poseidon,
{
    let context = GPU_CONTEXT.with(|cell| cell.get().cloned());
    let context = match context {
        Some(ctx) => ctx,
        None => {
            return None;
        }
    };

    Some(build_merkle_tree::<F>(context, leaves, cap_height))
}

/// GPU Merkle output that mirrors the CPU layout.
#[derive(Debug)]
pub struct GpuMerkleOutput<F: RichField> {
    pub digests: Vec<HashOut<F>>,
    pub cap: Vec<HashOut<F>>,
}
