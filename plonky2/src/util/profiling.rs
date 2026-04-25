//! Lightweight timing helpers that work on both native targets and wasm.

use core::future::Future;

use log::info;

/// Execute `action`, logging the elapsed time with `label`.
#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
pub fn with_timer<T, F>(label: &str, action: F) -> T
where
    F: FnOnce() -> T,
{
    let start = std::time::Instant::now();
    let output = action();
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    info!("{label} took {:.3} ms", elapsed_ms);
    output
}

/// Execute `action`, logging the elapsed time with `label`.
#[cfg(target_arch = "wasm32")]
pub fn with_timer<T, F>(label: &str, action: F) -> T
where
    F: FnOnce() -> T,
{
    let start = js_sys::Date::now();
    let output = action();
    let elapsed_ms = js_sys::Date::now() - start;
    info!("{label} took {:.3} ms", elapsed_ms);
    output
}

/// Fallback implementation when `std` is unavailable; simply runs the closure without logging.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "std")))]
pub fn with_timer<T, F>(_label: &str, action: F) -> T
where
    F: FnOnce() -> T,
{
    action()
}

/// Async variant of [`with_timer`] for operations that need `.await`.
#[cfg(all(not(target_arch = "wasm32"), feature = "std"))]
pub async fn with_timer_async<T, F, Fut>(label: &str, action: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let start = std::time::Instant::now();
    let output = action().await;
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    info!("{label} took {:.3} ms", elapsed_ms);
    output
}

/// Async variant of [`with_timer`] that works on wasm targets.
#[cfg(target_arch = "wasm32")]
pub async fn with_timer_async<T, F, Fut>(label: &str, action: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    let start = js_sys::Date::now();
    let output = action().await;
    let elapsed_ms = js_sys::Date::now() - start;
    info!("{label} took {:.3} ms", elapsed_ms);
    output
}

/// Fallback async implementation when `std` is unavailable.
#[cfg(all(not(target_arch = "wasm32"), not(feature = "std")))]
pub async fn with_timer_async<T, F, Fut>(_label: &str, action: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = T>,
{
    action().await
}
