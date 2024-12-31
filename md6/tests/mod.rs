#![no_std]

use digest::Digest;
use hex_literal::hex;

#[test]
fn test_md6_64() {
    const INPUT: &[(&[u8], &[u8; 8])] = &[
        (b"a", &hex!("32d13030a6815e95")),
        (b"aa", &hex!("af7966908a5d9c13")),
        (b"aaa", &hex!("3d8a4ff7a21eb0c6")),
        (b"aaaa", &hex!("5aafda0f42635bbe")),
        (b"aaaaa", &hex!("c370f6eceefb2c04")),
        (b"aaaaaa", &hex!("453f31fe99e3365d")),
        (b"aaaaaaa", &hex!("9d52c725c926756b")),
        (b"aaaaaaaa", &hex!("836d56b5756bd4d3")),
        (b"aaaaaaaaa", &hex!("2d27ed075595d38f")),
        (b"aaaaaaaaaa", &hex!("e31280f1a2fc2528")),
        (b"0", &hex!("17d073d4d38b5400")),
        (b"1", &hex!("870f87ac0bd00aee")),
        (b"2", &hex!("0d70630287b9031a")),
        (b"3", &hex!("f60aa0d9fa94116d")),
        (b"4", &hex!("1e6b0691ef4d4705")),
        (b"5", &hex!("6305b39e912c144b")),
        (b"6", &hex!("b47486289e236138")),
        (b"7", &hex!("dd018e6e7363124a")),
        (b"8", &hex!("eb456a3ae7348bf8")),
        (b"9", &hex!("15bc9eac62570fe7")),
        (b"md6", &hex!("b2f36109e52bd99f")),
        (b"md6 FTW", &hex!("47cda109418592ca")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_64::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_128() {
    const INPUT: &[(&[u8], &[u8; 16])] = &[
        (b"a", &hex!("bb691c1bfa4b4345292eb35f364919ea")),
        (b"aa", &hex!("19487e566f9ae2584d62628af2795f8c")),
        (b"aaa", &hex!("319f1b026f76f9caf62320b4e2e79e29")),
        (b"aaaa", &hex!("eb94dae524df4b84ba4a14115c3d0448")),
        (b"aaaaa", &hex!("07d01330b8af7013284b9b339378aac1")),
        (b"aaaaaa", &hex!("5638b2a1b7c5b66e963ea7744d1c9876")),
        (b"aaaaaaa", &hex!("2ad627c7c0e089c28824a354841e9215")),
        (b"aaaaaaaa", &hex!("1f7d2461fcfe705a7afadfabc9c95eb6")),
        (b"aaaaaaaaa", &hex!("aa74a4962cdc8b3ae4bacf8995e9fa68")),
        (b"aaaaaaaaaa", &hex!("623522019a5e40188a3b8956d44ea57d")),
        (b"0", &hex!("7464cb2427a4b04bc0ca92653711e3a5")),
        (b"1", &hex!("84a229d23cf5f380527c7dd9a887a384")),
        (b"2", &hex!("44bf1a90a89c4bf3d6668e7886226127")),
        (b"3", &hex!("cad8b9e548056c8ffd19cf469d1ac1ee")),
        (b"4", &hex!("78746de94a7ff50fa11d22119a3d6545")),
        (b"5", &hex!("ccc274bde4ebb8a38b6f19a8e0c022c0")),
        (b"6", &hex!("b19533319a23aa00af9d143db6655041")),
        (b"7", &hex!("3c049e4e57a5661b66c5235a07393bd1")),
        (b"8", &hex!("ba73bb10cf0fee5758f3f8b37cd9fdd4")),
        (b"9", &hex!("cc5f60133f81e505343174fa672d9f96")),
        (b"md6", &hex!("98b4a2b7363159f810a60432df277b7c")),
        (b"md6 FTW", &hex!("e866b430fa07b5bea28981db1f9b24a6")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_128::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_224() {
    const INPUT: &[(&[u8], &[u8; 28])] = &[
        (b"a", &hex!("05de8792a96e024c806eb815f9f30053cf9f1b50661047a4934121b7")),
        (b"aa", &hex!("a03a918a4d15e30c70b64a46374d8f3d97ac46bcd70176cc47fc6864")),
        (b"aaa", &hex!("bb30c438e8aad6ba79c826542087a82e8d0d233c50c945a2071abb25")),
        (b"aaaa", &hex!("bd4ecd894231f31df590f9e819600e363352b683b0acf0c84f69ede4")),
        (b"aaaaa", &hex!("3a01ad0af963adefdff3d4f19b18fc409dbc371f52183125ea35409a")),
        (b"aaaaaa", &hex!("b25d4fef8fef6de11074578de58c79da670dbfe2384c31e75b467be8")),
        (b"aaaaaaa", &hex!("972c4efe175501a60a5ae668969317006640c8a79af596b6388f80c9")),
        (b"aaaaaaaa", &hex!("d51f874f6ecc64526baf3d9acf1fdaaf25e5d7b0dd7a046cc5362a2d")),
        (b"aaaaaaaaa", &hex!("a9713653a744b7198ac66744488de95b67ed4f97a0eff17dc5b9f0ad")),
        (b"aaaaaaaaaa", &hex!("5672369481389de3fc4e5a678b071d328f2ff400b22c2aa226e72035")),
        (b"0", &hex!("61ac9c7608a733ae06b37ebd729dbd2395e08aa3e08c2e645f996e0c")),
        (b"1", &hex!("cbed1f15034d1a64e8ac4e4b61b20a1af88ce6b5975a66a31854f4b5")),
        (b"2", &hex!("94efb1ddb684213949647ed2b7fc7cfed3c39bb7e6e7a206ce96a12d")),
        (b"3", &hex!("74b69557a1caad60a0ff05605482c7683437a8cd84644b0ab511d629")),
        (b"4", &hex!("8986a064f4fc94675f32f278984a472d70898267063eae0efb46b5aa")),
        (b"5", &hex!("f42f6a4e12109d78a4fb1d701ea9447be6263bbdc7270c6da10fb78e")),
        (b"6", &hex!("55bfa088f6d6f63579a6e79ea9b5a17101d46821ce7624b03aeed66d")),
        (b"7", &hex!("48e4bbdb81eafab004a3067591765f75e10b835b04797912ce4ac6c9")),
        (b"8", &hex!("4c690ad845a62e6c6f765cb58b5707f19d01af419c122b0118c8223c")),
        (b"9", &hex!("a2ac8d05145172d6450806d84065211d14c712f3995dfbfbd05924a4")),
        (b"md6", &hex!("577f5287cf2d8e515d5f22fefb730ba4e8e0607fc7705c5b123036cc")),
        (b"md6 FTW", &hex!("7952f429ebbe134d302939817eff92e099b16273a2c3b0741614d8ad")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_224::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_256() {
    const INPUT: &[(&[u8], &[u8; 32])] = &[
        (b"a", &hex!("2b0a697a081c21269514640aab4d74ffafeb3c0212df68ce92922087c69b0a77")),
        (b"aa", &hex!("dc62c2f369d0d0a8de1d3239e312e12ac8c92d77d64262eb1fc209f8a2aaa48a")),
        (b"aaa", &hex!("84610026b18ef3019a73be33f9b084194ce6ef4cd7348ae5a390b2d20d3b45fe")),
        (b"aaaa", &hex!("28c490c3d4b0ad1809f59160b522ccd99c5a7565499b53af94bc311b3581a9f6")),
        (b"aaaaa", &hex!("40f8bab5ef49065851f602e062b7fa819497ea9e1aa9419ba70b3730f108d42f")),
        (b"aaaaaa", &hex!("ff01d77b95f1aa6dafa4813c75d5ba2900cbe399505097f9c4fb1d1e9b0a1ba0")),
        (b"aaaaaaa", &hex!("0107532d1a2c5028124135df7783c5177bc520d622c5bac3001e2c2e90011741")),
        (b"aaaaaaaa", &hex!("44e7e33cf46bc248a0476332f6d24c59252412d8db037470142eb66f1afdae11")),
        (b"aaaaaaaaa", &hex!("261ac535cae8a76b2e70c2b6f24e3fe5acf32f3d5db5662c8f933c90f84cfed1")),
        (b"aaaaaaaaaa", &hex!("3c74f2b9d89cf806cf0b529773ef09b8ed0b393afe166fa759f53d2cb6dfb40b")),
        (b"0", &hex!("d979642b9060ce2dc24183bf3ac6d9ae4b54f144d3af24935e9b8bc907a72b4e")),
        (b"1", &hex!("7fe3b063c891feb631ed0988895cfaf8a90fcb5a7d43c25f9dd1e1c21f896711")),
        (b"2", &hex!("1595783f79211f1d954c181f3573025020f9495f5763934ee25954ee7c2a83cc")),
        (b"3", &hex!("edae30bbeb946b55333732d7c5ad872da6ece3ba28cece17d14c2302b4f98a51")),
        (b"4", &hex!("8a1cb9446a2791e600879d214e50ab9f255c763f02043df556f3aad6e41d2b41")),
        (b"5", &hex!("632a4ef13a940fec5c41cadd550dcd41d491024da37cfc686cea53026a39c2e7")),
        (b"6", &hex!("bfed808c85097bd8bd45fe1b0223eb3a15c013af38c4a09a2e81f5eb2c2f6d43")),
        (b"7", &hex!("662e1312173e2bf826439e234367ceaab3b0d98af400907742ea2c01fec70d2a")),
        (b"8", &hex!("3edd4058e60c3e85c56341aaf8d037e3f3e5ff9233d17a66880616f3151de9ad")),
        (b"9", &hex!("6c9f735d57a9b12493b5c5c0ec9733b459f13e7e996edd090dda164ebfe43d54")),
        (b"md6", &hex!("cbe8da56ff91be9bc299ed4c1da6159f9a41ab380f565db0a5ef08895aed4f7d")),
        (b"md6 FTW", &hex!("7bfaa624f661a683be2a3b2007493006a30a7845ee1670e499927861a8e74cce")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_256::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_384() {
    const INPUT: &[(&[u8], &[u8; 48])] = &[
        (b"a", &hex!("a40c8d059495a278fadd30b96e3b2227758090c759b934197265bf632cabf8547a7429e5316d496c2a1ddae8d27e87ee")),
        (b"aa", &hex!("330547441b6518e7693ea01bfc55158bcfc084853fa1960a9e8999f98b57cea7d8b0564bf192b6ab1eb7638939dc9bbf")),
        (b"aaa", &hex!("f43bb4e108ec31e0cf8ded506f79373e69cddcd8c7c46298f1bd475401132e4c255c08e378c9db988f0de97131cbe36c")),
        (b"aaaa", &hex!("b848065d437013c8fda2493bbf240587ef5fd82a178416613e5c0077541c1ca33f205e58d49387d4d9e3cd62d2d104f6")),
        (b"aaaaa", &hex!("20ba7998f75c67dd1371cec629e0606739514cdfb32a17b94fa8ad4c4ec7a06a09821c93a16c863ff7ff72631b5ad02b")),
        (b"aaaaaa", &hex!("4930a7f1d619e219a12ca118f1a2f6dd9b23b32b366014b5d14976a927d4252e89d927b7c1d1e796aec3d2f3fd294287")),
        (b"aaaaaaa", &hex!("cf15b1b738f91476f2a139dda60e59f5e7422d7e99cb35d9bbb96f85c52a8e6542d4b08070c0855474946d86cc99fba3")),
        (b"aaaaaaaa", &hex!("7f9dba3ca2c4442eefd377877b168a2283576abd157c87cda401aa86c484669aa17326fe1e4a50dcca8cbe5bb5a0e947")),
        (b"aaaaaaaaa", &hex!("067d6be27eef07c654254a62275daa41630b9fd5d074badb2d16f0cf5e9621026ef0506649efebcf3a18bdf2b6a17a3a")),
        (b"aaaaaaaaaa", &hex!("f1fc124cbfa55170d508a26bdad017978bac8be6899f1a99f420c94bd1ef8d5547bf36488e8824215cf5da878041cf76")),
        (b"0", &hex!("9a97b926552bb7bc61015e43e9430e3c49a76724c6d6e0b31c14f9c5bb4c7dbf78d5c583401976da7139819dc16c5934")),
        (b"1", &hex!("103644563cda42ea432d325fed2b0977f0d767f475b4794322916b7d82b24308c11389a6fe2acf6cade70ddf990da337")),
        (b"2", &hex!("dcfdb3807231f3c5d0da945e0cc83f1d2368479f059c46841b112796bca717b4acce887877062e60f3af0276a43eb13d")),
        (b"3", &hex!("37e21bffcc21b6de5d3bbae971d9e889670e9c77ad8f42558caea4e59fea1efb7b3392ca53a294b862b04893cdf0a4f6")),
        (b"4", &hex!("aaf0b2fd043fc3f2e247f02ab1618b1450db799174bf6fae883822b7cf145d7080c5b70899c10ebb7a4221c9ab36070b")),
        (b"5", &hex!("4d59a67f4c321eb971d7bd26a0c8e3ff7a023bb7c15097aa9b13a94fce91b24cf82ce09acac63f63f1da708ecfe49427")),
        (b"6", &hex!("36886709330eae549c25558ac0d4ae2b7082261e76d33d589379d3ada613eb31943bf8dda1e92fbc7001fa6f407b025e")),
        (b"7", &hex!("9124c888a99743a90daa8a3032014c6542f0e4ed949e950e3a2ff4945ae9f7c648dc6bf712a5556edaed50e7dc299007")),
        (b"8", &hex!("41b469911cebb00f5ab173e5238fe4e6aa1737f21159f550913b7b30c99d8c2c1ecd2c431f0baa992eccc5a9cfddf782")),
        (b"9", &hex!("9211ce0b1ae366def2d9337c34e4b1ea75ac93efab88c273ce691ed7d20da8d0bd8cbd8d2341e7a619705fcb4eeda311")),
        (b"md6", &hex!("1aa5bb36a472fdb3d19ae8b3aa84773ab9a8e7e13d0fde914488bba066d64d5309155ea5b7a3b33b4d9d6855fa9050b1")),
        (b"md6 FTW", &hex!("7a4e8ecd1035ccdf00567595c15aa5a382fef2b6a4ec4bc609e0c655887b1c05e10eee223dd6c0ba5fa4a46159c70757")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_384::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_512() {
    const INPUT: &[(&[u8], &[u8; 64])] = &[
        (b"a", &hex!("c0e4e18acb69cd1a7e5a20981fe6cc6f7b5b70e814d3a13b05ac292aba74c0d8c9d34c211414e7ab755a9559c27211cd749fc3eb09ae670e138881743b8d5051")),
        (b"aa", &hex!("2afa253b05702770343e5c46e9d47231812a741d7bba479539a3c5484a412ea419f0d0ca96e124ba92e4ca506ca12684579323051d9d52fe5a669d079a226683")),
        (b"aaa", &hex!("56b0131875d458f6d30ed1c594991df1efa8d6cae0c8abb36a9b811df23ac476c58e36d9adbe845e840d3de9175a8ceda11235144c3222587af108b902ce0fc5")),
        (b"aaaa", &hex!("26a0bbf7df198fef1aa1945ebb91e7a9436e0892f4cdd5ee18e8dfe533f45da50c36debe4d98d0eae21925403e0d37603ea67f136b3076a1e053421052971480")),
        (b"aaaaa", &hex!("86da00c33edf5d1daff144312af7e1a37f6441fc9905feb8caf4023fb6b34951464dc276a29925e3ad796cbdb7a09febd7d985c21702cc1b1c849e604de6580b")),
        (b"aaaaaa", &hex!("7e67f0540f2afd27a17ff7a8be74039b79ff060a69b6f8fb98e3afc8e0a828fffb35aff2f3e20569933ef7c418fb3a8d7cfc7c17f3360a6ecca2a800c6657592")),
        (b"aaaaaaa", &hex!("08d8eb85e5fe6b8e0f81841e9373de9ed18f14e911506a81cbd4e388535632edc425c88c1acbaefd61e98ea59fcda024acf662f79791acb3d15e935aa482dfef")),
        (b"aaaaaaaa", &hex!("2db495253418869d64c3be65f304f0f73f87da659d1aa3ad457fa437e9370bf24f88b5c28c3c0dd4e67b351499ea380b60cb0010ffd28ac2449d5361925c8ce7")),
        (b"aaaaaaaaa", &hex!("6d12438e615b0c1171678d262ba429a6ee58a87e24eb7b2fa0d5bec70bba1ea2e43acef122b1ca5de1a414153b0a12d795abed88cf3e88f26bf59a3222b04b99")),
        (b"aaaaaaaaaa", &hex!("c4451dcd12d3847e1f2408ed3c9cc2f79a179ddf5a0a9246b68adcf918bbcea67f6c8721cc226599d587313895b8a8d53881061014b6444f3d3464b03602ecc2")),
        (b"0", &hex!("057e1c40468ab5661defdbcd3bf671d398116373db2e7ab0adc6b0871d603eda39cf7255361ca456543157fbe09847b501586d701d53564fab651bd2f49dcda4")),
        (b"1", &hex!("0f19bc75955c2e405620d5a69d3ce7078c11c3805523cbd5ff834704af67d40c65e9f011fdd3723fea365eb6fa744b981fc9cd53928edae43eaa942158a649d5")),
        (b"2", &hex!("5f68d3c677d9cde81417f92889287e94141ff212080b1bb8d4485b01061dc0bccd8eed96fe728ea5ff3596201225337ebbf06ae6cf6162290843dfd226f7d647")),
        (b"3", &hex!("f4243d7945b667900c78b894d83a343b2e8865ff62cef11e51a20472600df8a17a026d3ce09cb85925540a1515b34210bdd8eed76b8fe37f35cdc5350bb7bd19")),
        (b"4", &hex!("8a1b250daf9fc0b2b5878504991b8950ed7c621e0b9163fbcb5f34b363f22fd6be96ed4a9c5aacbc9d6e30de4e97090a5758f89b6ae61b45658b2f79ec26fc51")),
        (b"5", &hex!("ad6fa2a0f8e35189d5d070559124bd6cbb1170969356165dfda720b4ded83fd14ee8d81a2ef30d918ebcfc01d668950ba681bedcc3e1180b76c06a55e9a11497")),
        (b"6", &hex!("2e2bb4d681f61821c6c470064b83b924cf691de74ed05bd8610cef5397d7e2c4aeda1930446f306dece4bbefe4fc87168d7a15ab80c890672b676a532739bc67")),
        (b"7", &hex!("adb9009ae9abf8444d45a62b7adafcaef48c6ee7c48fa65d206d7a58ac3a5993e2eb81120d45338b9f9aa1b100365e2a98cd59fd7062783e5d23088b562176c3")),
        (b"8", &hex!("516315942af5bbd028a533420a6496b77ca707a0b5dd0b473359d9bb74bdd00a59987a881c774a59dd2c62f1759f570713b881a622a70894ff319881e07cfd34")),
        (b"9", &hex!("b98f4b7c5cecda77117180a38be5bda00bf72b7e4106c0d00137d269a0d48eb571004a8069f25fab4c2b4b16ab118af881eb904f9f32331dc726c1a404489604")),
        (b"md6", &hex!("e94595891b2b3e2b2e3ae6943c17a34703c4230296f12f1689264e46518e0e1b0106996387ad6d8ec9b9c86e54301a71e6f4dab6e7369db4e503daae64f2e0a1")),
        (b"md6 FTW", &hex!("75df3b6031e8241ef59d01628b093b05906f1a2d80c43908cb2883f7db6fbdd1cadffd7d643505c20b9529b6a5d19f8b6ff1623cabbc14a606caa7bcb239611a")),
    ];

    for (msg, &expected_hash) in INPUT.iter() {
        let mut hasher = md6::Md6_512::new();
        hasher.update(msg);
        let output = hasher.finalize();
    
        assert!(output.to_vec() == expected_hash);
    }
}

#[test]
fn test_md6_var() {
  use md6::{Update, VariableOutput};

  let mut hasher = md6::Md6Var::new(12).unwrap();
  hasher.update(b"hello rust");
  let mut buf = [0u8; 12];
  hasher.finalize_variable(&mut buf).unwrap();
  assert_eq!(buf, hex!("9c5b8d9744898ec981bcc573"));
}