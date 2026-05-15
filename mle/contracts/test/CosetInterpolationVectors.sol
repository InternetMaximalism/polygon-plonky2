// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.25;

/// AUTO-GENERATED — do not hand-edit.
/// Regenerate via:
///   cargo test --release --test dump_coset_test_vectors \
///       --features std -- --nocapture > \
///       mle/contracts/test/CosetInterpolationVectors.sol
///
/// Each `vector_kK_degD()` returns:
///   wires:    the gate's local-wires slice (random Goldilocks elements,
///             not necessarily satisfying the constraints — the point is
///             bit-exact match between the Rust evaluator and the
///             Solidity port, not constraint validity).
///   expected: the per-constraint base-field values that
///             `CosetInterpolationGate::eval_unfiltered_base_one`
///             writes (length = `4 · (num_intermediates + 1)`).
library CosetInterpolationVectors {

    /// subgroup_bits = 1, max_degree (constructor arg) = 2 (effective degree = 2)
    function vector_k1_d2() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](11);
        wires[0] = 0xa40abecf9c53553b;
        wires[1] = 0x092ea010c1770f66;
        wires[2] = 0x94017ba6b9c7029b;
        wires[3] = 0xdaca53c087d3be1e;
        wires[4] = 0xc27952b198411ad3;
        wires[5] = 0xf049daf39512efcd;
        wires[6] = 0xa47599895070f736;
        wires[7] = 0x5b78af7255089497;
        wires[8] = 0x99adfdecda0a3921;
        wires[9] = 0x7339b6eb183a289b;
        wires[10] = 0x8ef00255f9789882;
        uint256[] memory expected = new uint256[](4);
        expected[0] = 0xfb8e32e46443324d;
        expected[1] = 0x2d6ddbd4b0b7e492;
        expected[2] = 0x15fda83d3211576f;
        expected[3] = 0x63578877e4dbd073;
        return (wires, expected);
    }

    /// subgroup_bits = 2, max_degree (constructor arg) = 2 (effective degree = 2)
    function vector_k2_d2() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](23);
        wires[0] = 0xb7cbe96f5c46f764;
        wires[1] = 0x3e12d4ab84511dcc;
        wires[2] = 0x574336787b9c9b35;
        wires[3] = 0xb7cd57a33df837a7;
        wires[4] = 0xf69dd2002b5cfb01;
        wires[5] = 0x6204b7a5821b122f;
        wires[6] = 0x22e929706fe8ff5c;
        wires[7] = 0xac8f6846691b9443;
        wires[8] = 0x9341a83b7382d0de;
        wires[9] = 0x0a69fecbc2933070;
        wires[10] = 0x99e6853e27936ac2;
        wires[11] = 0x8bc7351eea382d8f;
        wires[12] = 0x49ee22743e617d0c;
        wires[13] = 0x92db55565fff8176;
        wires[14] = 0x9543c1ed8521452b;
        wires[15] = 0xf93ea963b856c106;
        wires[16] = 0x182c20e40d8715f6;
        wires[17] = 0xf60b06f120a5b054;
        wires[18] = 0xd4a4f2119f8e0167;
        wires[19] = 0xea1e850435280140;
        wires[20] = 0x0fd8ea64e4312f52;
        wires[21] = 0x9c0b30942058fa8a;
        wires[22] = 0x7e3c2600793de536;
        uint256[] memory expected = new uint256[](12);
        expected[0] = 0xf91ba0e21547e20f;
        expected[1] = 0x4d8c62ca7a533b36;
        expected[2] = 0xd52d7caa4685019b;
        expected[3] = 0xf11c735311628738;
        expected[4] = 0xff1dedf9b6516e1e;
        expected[5] = 0x28b8cf1858a772ed;
        expected[6] = 0x1439995767967f46;
        expected[7] = 0xa7d2e7675dfa38a5;
        expected[8] = 0x07bb6c22c5f62772;
        expected[9] = 0x4113f6c8e44c68f4;
        expected[10] = 0x2a03a49bb94dea5b;
        expected[11] = 0x7977f58d18dc5c2c;
        return (wires, expected);
    }

    /// subgroup_bits = 2, max_degree (constructor arg) = 3 (effective degree = 3)
    function vector_k2_d3() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](19);
        wires[0] = 0xbbeddf601d9e57fd;
        wires[1] = 0x9ce7cf3d92b16a91;
        wires[2] = 0xf8a32a02e9b3135a;
        wires[3] = 0x7da4e5ac4bde1e71;
        wires[4] = 0x50b340585f28d128;
        wires[5] = 0x78e77bbbeeda84de;
        wires[6] = 0xde5397d500e9fc35;
        wires[7] = 0x3084b612db3b5388;
        wires[8] = 0xeb7b76e82d9b261a;
        wires[9] = 0xd41cb48d6f745fdb;
        wires[10] = 0x2677055724096c1e;
        wires[11] = 0xeddef1170000bdc1;
        wires[12] = 0x3361175aa6c15e12;
        wires[13] = 0x501f421e1dd1fea5;
        wires[14] = 0x42235e392653e235;
        wires[15] = 0xcaec0b47ceadc998;
        wires[16] = 0x0b773cca498631c7;
        wires[17] = 0x3eb525f060fb9e30;
        wires[18] = 0x5071f0b22cfe1bf8;
        uint256[] memory expected = new uint256[](8);
        expected[0] = 0x88a4840c3e0cd452;
        expected[1] = 0x793a1d08a1e9e273;
        expected[2] = 0x07c2f9a1d15ae899;
        expected[3] = 0xe9e421a366d41d26;
        expected[4] = 0x5e19eb7663cec65d;
        expected[5] = 0xadcf07cb2fcd3b08;
        expected[6] = 0x37b54174fbdfe8e2;
        expected[7] = 0xfa40abda85e0f012;
        return (wires, expected);
    }

    /// subgroup_bits = 3, max_degree (constructor arg) = 2 (effective degree = 2)
    function vector_k3_d2() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](47);
        wires[0] = 0x906bc6e28ea5ff58;
        wires[1] = 0x135ae14f9d4bc5b9;
        wires[2] = 0xc8a09f6ed54841a9;
        wires[3] = 0x9c91dbac55e123ae;
        wires[4] = 0xbacde7801d12f26e;
        wires[5] = 0xf3214ac75e44bd71;
        wires[6] = 0x4ed94c03b6b7d8f3;
        wires[7] = 0xd0de372f09237ae7;
        wires[8] = 0x2fbd700a67dfe565;
        wires[9] = 0xbc7d7a6e2fe31df8;
        wires[10] = 0x1429b0bd5d7bb698;
        wires[11] = 0x09943eeef30f3ca5;
        wires[12] = 0xaf865a3ae48f5c4f;
        wires[13] = 0xf57c9a2fd8a105f8;
        wires[14] = 0x8da7dde640a605d0;
        wires[15] = 0xcccf97113483d5f9;
        wires[16] = 0x0284c4f6755bd6b8;
        wires[17] = 0x690809ddc85135b4;
        wires[18] = 0xa8493a215f07345e;
        wires[19] = 0xff1834301a83ccab;
        wires[20] = 0x5752b2ba50bebd24;
        wires[21] = 0x1553426e27064892;
        wires[22] = 0x3f23551031bcde59;
        wires[23] = 0x9727ff8518646c3c;
        wires[24] = 0xc85ac6f84c694c79;
        wires[25] = 0x3cc4da950621bd42;
        wires[26] = 0xe096e870693a23eb;
        wires[27] = 0x916fd8ff10d1eebb;
        wires[28] = 0x7a78369e8b44e1f5;
        wires[29] = 0x05828d47599e1f2c;
        wires[30] = 0xd027fc8b465eca05;
        wires[31] = 0xa4638ed14236098f;
        wires[32] = 0xaf3513d52d3b44e7;
        wires[33] = 0xf3334d08e280aa6a;
        wires[34] = 0x66109139de065c75;
        wires[35] = 0xa517c319ce3214d5;
        wires[36] = 0x8a3fd821826ad8c2;
        wires[37] = 0xa092dbada81870fd;
        wires[38] = 0x83138a95b525a41b;
        wires[39] = 0xc0df7a84b994b1b6;
        wires[40] = 0x37052d781ac0eb7f;
        wires[41] = 0x37c67c302f4deb75;
        wires[42] = 0x180cea6bc6260b08;
        wires[43] = 0xb178c00cf0fbd4f7;
        wires[44] = 0x546262571682a6b9;
        wires[45] = 0x48bc7f6595544000;
        wires[46] = 0xfe513e84489158bc;
        uint256[] memory expected = new uint256[](28);
        expected[0] = 0xe53a044cfd916cc2;
        expected[1] = 0xe027453a2ddfc4b9;
        expected[2] = 0x47d113891f6195e5;
        expected[3] = 0xfe283c37a3410b9d;
        expected[4] = 0xca682ba5031aedfb;
        expected[5] = 0x0e524e045e507e93;
        expected[6] = 0xd139cb8aaefc7745;
        expected[7] = 0x452ece56bfc44a51;
        expected[8] = 0x881d09000bd6eb5a;
        expected[9] = 0x196abd5dffd46c10;
        expected[10] = 0xb54ae5dd82dc1218;
        expected[11] = 0xa62a3d471da94175;
        expected[12] = 0x549cbd47ab05652c;
        expected[13] = 0xb80d40d4d0b50807;
        expected[14] = 0x90400c60bf6e479b;
        expected[15] = 0x066107c0b8d65a60;
        expected[16] = 0x4f69273879956517;
        expected[17] = 0xfca6c668205f9315;
        expected[18] = 0xcf1741f900be9805;
        expected[19] = 0x40e61bab774a7c89;
        expected[20] = 0x08fd8424a849bab3;
        expected[21] = 0x13276aba3ccea206;
        expected[22] = 0xfca906837fb287c7;
        expected[23] = 0x171dfecd0f4c984b;
        expected[24] = 0xbe8b0ac0a3fd695d;
        expected[25] = 0xc14ce57413116fd6;
        expected[26] = 0xffe750e35e18f179;
        expected[27] = 0xd93c52ddc72e119a;
        return (wires, expected);
    }

    /// subgroup_bits = 3, max_degree (constructor arg) = 4 (effective degree = 4)
    function vector_k3_d4() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](31);
        wires[0] = 0xc2c9326fbac3ec2b;
        wires[1] = 0xb9c36071e798d29d;
        wires[2] = 0x0142c82117d545e3;
        wires[3] = 0x44585e1abb682155;
        wires[4] = 0x047f4e74a30baac1;
        wires[5] = 0xcd0162f9b8564df1;
        wires[6] = 0x8ccee1e838c0a2ae;
        wires[7] = 0x624f63ea829b18b6;
        wires[8] = 0x3187c0d9d9ac370f;
        wires[9] = 0xf11260c8c9db5797;
        wires[10] = 0x822f8b2606bec930;
        wires[11] = 0x21b56d28ba7521f8;
        wires[12] = 0xb2bb474a74642a92;
        wires[13] = 0x70d9bda897605bbc;
        wires[14] = 0xcbacdd17adb6e718;
        wires[15] = 0x9994aa86bc57f59b;
        wires[16] = 0xf96b7604a37b94d4;
        wires[17] = 0x4769cac6527aa3df;
        wires[18] = 0x2c216d70cdadc8c3;
        wires[19] = 0xa35a8f0ff4c95833;
        wires[20] = 0xceeb109ecbfb2f37;
        wires[21] = 0x98c7562eb507e9c2;
        wires[22] = 0x701c97d958b8125c;
        wires[23] = 0xc592d8753389b768;
        wires[24] = 0x9c67bae9f2299b75;
        wires[25] = 0xc60e90c43ee3bc2d;
        wires[26] = 0xdf8306eb82367c8c;
        wires[27] = 0x1ad82bb9a46e0331;
        wires[28] = 0xbd77a390b1360b27;
        wires[29] = 0x22c6efef5ef9a0fe;
        wires[30] = 0x3dbe7b676d0dec32;
        uint256[] memory expected = new uint256[](12);
        expected[0] = 0xb7f30179fc87375e;
        expected[1] = 0x4a5774db03146d63;
        expected[2] = 0xa51cacb0259ff71c;
        expected[3] = 0x50e4ec40cf40e14f;
        expected[4] = 0x1549880a93491973;
        expected[5] = 0x71145a9e6847905e;
        expected[6] = 0x3cd1f0dc9ce61e04;
        expected[7] = 0x7c956f1689f7ae06;
        expected[8] = 0xcacaa550316ff06f;
        expected[9] = 0xb1a9840622e0bc2c;
        expected[10] = 0x8a67f02ba5ac6483;
        expected[11] = 0x3f4d338a8a293480;
        return (wires, expected);
    }

    /// subgroup_bits = 4, max_degree (constructor arg) = 4 (effective degree = 4)
    function vector_k4_d4() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](55);
        wires[0] = 0xa20d24ebdd0e36b9;
        wires[1] = 0xf5cfb3fab0e0aeab;
        wires[2] = 0xa00fa28f310177bd;
        wires[3] = 0x164a2a11a1a67aa3;
        wires[4] = 0x240c0883ccebd715;
        wires[5] = 0xe229ebe2270b89f5;
        wires[6] = 0x71db5d246c77f618;
        wires[7] = 0xca324c7f6483bc8b;
        wires[8] = 0xaedd7a99605617e4;
        wires[9] = 0xee451bbbb5246913;
        wires[10] = 0xc4f5ccbd12af94e0;
        wires[11] = 0x2a2d177bc5936bbb;
        wires[12] = 0xd998d9d5c0875f8b;
        wires[13] = 0x57d3b65e0395a18b;
        wires[14] = 0x21f2b2fe80023b08;
        wires[15] = 0xc17d225506e36e9c;
        wires[16] = 0x8a76e7500a740ee1;
        wires[17] = 0x290585febfccc336;
        wires[18] = 0xf9fa02a8631923b5;
        wires[19] = 0x7edc4f1c7fa23721;
        wires[20] = 0x83e8304c3fbe9839;
        wires[21] = 0xb85af69f8b87d05e;
        wires[22] = 0x31cc0e1f7f59fb29;
        wires[23] = 0xaa49a55975204598;
        wires[24] = 0x2c041a979d5dee0d;
        wires[25] = 0x17a082664070c25f;
        wires[26] = 0x0bb2e9e0d4e48630;
        wires[27] = 0x799c0e97cdcdd184;
        wires[28] = 0xdcffd73b03b5cfb6;
        wires[29] = 0x967dc2d8416ba0ff;
        wires[30] = 0x66f425ace0d2b6c5;
        wires[31] = 0xc6e146f988e7dd55;
        wires[32] = 0x8c85f4dd6fe3556b;
        wires[33] = 0x5d1477682f7d52de;
        wires[34] = 0x8a08fc9c5e022fe6;
        wires[35] = 0xf6619dabc6bc9ae0;
        wires[36] = 0x4db8b4ea492a66cf;
        wires[37] = 0x25c73e8cc1400856;
        wires[38] = 0x757b8e93ec17de99;
        wires[39] = 0x1a99a073b51b4513;
        wires[40] = 0xa1b132fd7c185992;
        wires[41] = 0x564b3c529b1488ec;
        wires[42] = 0x3d3552354374e76e;
        wires[43] = 0x36ce2e1ed9412262;
        wires[44] = 0xceeb23a2f5883d44;
        wires[45] = 0xf5f30446a06db1c1;
        wires[46] = 0x3583ddcf55c95cfc;
        wires[47] = 0xc0fe95d04741079b;
        wires[48] = 0xaca8765efe254cd9;
        wires[49] = 0xef058b3d4563a265;
        wires[50] = 0x11ddc78e62583ee2;
        wires[51] = 0xa8232e1de909bfa7;
        wires[52] = 0xb0cc9beb413a9c25;
        wires[53] = 0x6f019d6a51f4ac44;
        wires[54] = 0x5effee6c5c261e06;
        uint256[] memory expected = new uint256[](20);
        expected[0] = 0x3720e080469f37b4;
        expected[1] = 0xd97c5cdc58402da2;
        expected[2] = 0x5902ffa54d8314b7;
        expected[3] = 0x7f788ce1b3a8fcd8;
        expected[4] = 0xdd0868bdc23444be;
        expected[5] = 0x4bed131cd785f339;
        expected[6] = 0x297e0c1d9243bfbf;
        expected[7] = 0x67f1c78109296b55;
        expected[8] = 0x6dda74956ffa10bf;
        expected[9] = 0xa1fc1d2fe1f2cc8c;
        expected[10] = 0xa09dd40304e134da;
        expected[11] = 0xed63f4e84bcb76ac;
        expected[12] = 0x6b0593331079c7d7;
        expected[13] = 0xd9494528dbe90ecd;
        expected[14] = 0x7316588a23c38550;
        expected[15] = 0x3330467d5bf979a6;
        expected[16] = 0xe16abc749e224270;
        expected[17] = 0xcd2225e8a457e9d3;
        expected[18] = 0x8e92077200c7cae6;
        expected[19] = 0xab842bc47289e944;
        return (wires, expected);
    }

    /// subgroup_bits = 4, max_degree (constructor arg) = 6 (effective degree = 6)
    function vector_k4_d6() internal pure returns (uint256[] memory, uint256[] memory) {
        uint256[] memory wires = new uint256[](47);
        wires[0] = 0x22e86f586b6f97de;
        wires[1] = 0xdd4c06f7c8b09001;
        wires[2] = 0xaf1b2052fab662dd;
        wires[3] = 0xdcc432949407143b;
        wires[4] = 0x501ab786fa9318c9;
        wires[5] = 0x34f4005714f1f2c8;
        wires[6] = 0x53f8e2ab5c86520e;
        wires[7] = 0xf6997b04611a67f0;
        wires[8] = 0xeb3f9255bb381c0a;
        wires[9] = 0x527afff5441c62e0;
        wires[10] = 0x9b5d67f2ec70ae64;
        wires[11] = 0xe73722f7fb500ca7;
        wires[12] = 0x1e938a061f27c68f;
        wires[13] = 0xa61e253cb15732c5;
        wires[14] = 0x0949ca64a003dcbf;
        wires[15] = 0x759b76d63fedbf5f;
        wires[16] = 0x3844e7bd5e11239c;
        wires[17] = 0x7a32458980c1f19f;
        wires[18] = 0x19ffa092d0d7f3b9;
        wires[19] = 0xfff84de4c6139057;
        wires[20] = 0x724dd752f038221f;
        wires[21] = 0xd1e9dce76e465580;
        wires[22] = 0x1630688cf61c4cac;
        wires[23] = 0x2a69e8f924920218;
        wires[24] = 0xbd2a51618f214108;
        wires[25] = 0x9cd8246af14370b9;
        wires[26] = 0x3f13e9efeede9713;
        wires[27] = 0x434e7576efac3f97;
        wires[28] = 0x651b1e626fd90e10;
        wires[29] = 0x6b7e7befb5700292;
        wires[30] = 0x967a2ca58d470085;
        wires[31] = 0x18f697c01273867a;
        wires[32] = 0x54de2910fde310d8;
        wires[33] = 0x1a5d04e39084292b;
        wires[34] = 0x10555d8e6e29d27b;
        wires[35] = 0x1558df9e9570cc73;
        wires[36] = 0xfbaa9caed9735843;
        wires[37] = 0x4354f2ee775b033b;
        wires[38] = 0xad6dffdf815c54bf;
        wires[39] = 0x8851a6695833c42d;
        wires[40] = 0xd2d8046953613035;
        wires[41] = 0x6bd002d5779a52d2;
        wires[42] = 0xbe73a084f329f972;
        wires[43] = 0x16080a9a3abc40a0;
        wires[44] = 0xfc72d0f3e4a943fc;
        wires[45] = 0xc8a4a51dd86dfdfd;
        wires[46] = 0x113c55b73bcd0434;
        uint256[] memory expected = new uint256[](12);
        expected[0] = 0xc462ad94862a7120;
        expected[1] = 0x7b73466039d63c6e;
        expected[2] = 0xc91490ffdf3abcb6;
        expected[3] = 0xe3c9d3c770a06f45;
        expected[4] = 0xe384c2d39150cc42;
        expected[5] = 0xab27e7377c51eb92;
        expected[6] = 0xb8b0f0f4aa6a1422;
        expected[7] = 0xdead5495c2c7f2d2;
        expected[8] = 0xbd04ac9d40549144;
        expected[9] = 0x3e3726ad479c797e;
        expected[10] = 0xbd3c34a8d45b7c38;
        expected[11] = 0x3a0a04e66f20eaab;
        return (wires, expected);
    }

    /// (subgroup_bits, effective_degree) for each vector.
    function combos() internal pure returns (uint256[2][] memory cs) {
        cs = new uint256[2][](7);
        cs[0] = [uint256(1), uint256(2)];
        cs[1] = [uint256(2), uint256(2)];
        cs[2] = [uint256(2), uint256(3)];
        cs[3] = [uint256(3), uint256(2)];
        cs[4] = [uint256(3), uint256(4)];
        cs[5] = [uint256(4), uint256(4)];
        cs[6] = [uint256(4), uint256(6)];
    }
}
