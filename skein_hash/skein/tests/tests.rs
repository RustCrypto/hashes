extern crate skein;

const CONFIG_0256_0128 : [u64;4] = [
    0xE1111906964D7260, 0x883DAAA77C8D811C, 0x10080DF491960F7A, 0xCCF7DDE5B45BC1C2];

const CONFIG_0256_0160 : [u64;4] = [
    0x1420231472825E98, 0x2AC4E9A25A77E590, 0xD47A58568838D63E, 0x2DD2E4968586AB7D];

const CONFIG_0256_0224 : [u64;4] = [
    0xC6098A8C9AE5EA0B, 0x876D568608C5191C, 0x99CB88D7D7F53884, 0x384BDDB1AEDDB5DE];

const CONFIG_0256_0256 : [u64;4] = [
    0xFC9DA860D048B449, 0x2FCA66479FA7D833, 0xB33BC3896656840F, 0x6A54E920FDE8DA69];

const CONFIG_0512_0128 : [u64;8]= [
    0xA8BC7BF36FBF9F52, 0x1E9872CEBD1AF0AA, 0x309B1790B32190D3, 0xBCFBB8543F94805C,
    0x0DA61BCD6E31B11B, 0x1A18EBEAD46A32E3, 0xA2CC5B18CE84AA82, 0x6982AB289D46982D];

const CONFIG_0512_0160 : [u64;8] = [
    0x28B81A2AE013BD91, 0xC2F11668B5BDF78F, 0x1760D8F3F6A56F12, 0x4FB747588239904F,
    0x21EDE07F7EAF5056, 0xD908922E63ED70B8, 0xB8EC76FFECCB52FA, 0x01A47BB8A3F27A6E];

const CONFIG_0512_0224 : [u64;8] = [
    0xCCD0616248677224, 0xCBA65CF3A92339EF, 0x8CCD69D652FF4B64, 0x398AED7B3AB890B4,
    0x0F59D1B1457D2BD0, 0x6776FE6575D4EB3D, 0x99FBC70E997413E9, 0x9E2CFCCFE1C41EF7];

const CONFIG_0512_0256 : [u64;8] = [
    0xCCD044A12FDB3E13, 0xE83590301A79A9EB, 0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
    0xEC06025E74DD7683, 0xE7A436CDC4746251, 0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13];

const CONFIG_0512_0384 : [u64;8] = [
    0xA3F6C6BF3A75EF5F, 0xB0FEF9CCFD84FAA4, 0x9D77DD663D770CFE, 0xD798CBF3B468FDDA,
    0x1BC4A6668A0E4465, 0x7ED7D434E5807407, 0x548FC1ACD4EC44D6, 0x266E17546AA18FF8];

const CONFIG_0512_0512 : [u64;8] = [
    0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
    0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33];

const CONFIG_1024_0384 : [u64;16] = [
    0x5102B6B8C1894A35, 0xFEEBC9E3FE8AF11A, 0x0C807F06E32BED71, 0x60C13A52B41A91F6,
    0x9716D35DD4917C38, 0xE780DF126FD31D3A, 0x797846B6C898303A, 0xB172C2A8B3572A3B,
    0xC9BC8203A6104A6C, 0x65909338D75624F4, 0x94BCC5684B3F81A0, 0x3EBBF51E10ECFD46,
    0x2DF50F0BEEB08542, 0x3B5A65300DBC6516, 0x484B9CD2167BBCE1, 0x2D136947D4CBAFEA];

const CONFIG_1024_0512 : [u64;16] = [
    0xCAEC0E5D7C1B1B18, 0xA01B0E045F03E802, 0x33840451ED912885, 0x374AFB04EAEC2E1C,
    0xDF25A0E2813581F7, 0xE40040938B12F9D2, 0xA662D539C2ED39B6, 0xFA8B85CF45D8C75A,
    0x8316ED8E29EDE796, 0x053289C02E9F91B8, 0xC3F8EF1D6D518B73, 0xBDCEC3C4D5EF332E,
    0x549A7E5222974487, 0x670708725B749816, 0xB9CD28FBF0581BD1, 0x0E2940B815804974];

const CONFIG_1024_1024 : [u64;16] = [
    0xD593DA0741E72355, 0x15B5E511AC73E00C, 0x5180E5AEBAF2C4F0, 0x03BD41D3FCBCAFAF,
    0x1CAEC6FD1983A898, 0x6E510B8BCDD0589F, 0x77E2BDFDC6394ADA, 0xC11E1DB524DCB0A3,
    0xD6D14AF9C6329AB5, 0x6A9B0BFC6EB67E0D, 0x9243C60DCCFF1332, 0x1A1F1DDE743F02D4,
    0x0996753C10ED0BB8, 0x6572DD22F2B4969A, 0x61FD3062D00A579A, 0x1DE0536E8682E539];

fn print_blocks(a : *const u64, b : *const u64, word_len : usize){
    let a_pointer : u64 = a as u64;
    let b_pointer : u64 = b as u64;
    unsafe{
        println!("expected:");
        for i in 0..word_len{
            print!("{:016X}  ", *((a_pointer + (8*i) as u64)as *const u64));

        }
        println!("\n");
        println!("but got this instead:");
        for i in 0..word_len{
            print!("{:016X}  ", *((b_pointer + (8*i) as u64)as *const u64));

        }
    }
    println!("\n");
}


fn compare_blocks(a : *const u64, b : *const u64, word_len : usize)->bool{
    let a_pointer : u64 = a as u64;
    let b_pointer : u64 = b as u64;
    unsafe{
        for i in 0..word_len{
            if *((a_pointer + (8*i) as u64)as *const u64) != *((b_pointer + (8*i) as u64)
            as *const u64){
                print_blocks(a,b,word_len);
                return false;
            }
        }
    }
    return true;
}

#[test]
fn test_configurations_0256(){
    let mut ubi_chain : skein::typedefs::UbiChainBlock;
    let mut hash_len : u64;
    let mut test_result : bool;

    ubi_chain = skein::typedefs::UbiChainBlock::new(256);

    hash_len = 128;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0256_0128[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,4);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(256);
    hash_len = 160;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0256_0160[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,4);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(256);
    hash_len = 224;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0256_0224[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,4);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(256);
    hash_len = 256;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0256_0256[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,4);
    assert_eq!(test_result, true);
}

#[test]
fn test_configurations_0512(){
    let mut ubi_chain : skein::typedefs::UbiChainBlock;
    let mut hash_len : u64;
    let mut test_result : bool;

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);

    hash_len = 128;
    println!("raw hash len {:016X}  ",hash_len);

    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0128[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);
    hash_len = 160;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0160[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);
    hash_len = 224;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0224[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);
    hash_len = 256;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0256[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);
    hash_len = 384;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0384[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(512);
    hash_len = 512;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_0512_0512[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,8);
    assert_eq!(test_result, true);
}

#[test]
fn test_configurations_1024(){
    let mut ubi_chain : skein::typedefs::UbiChainBlock;
    let mut hash_len : u64;
    let mut test_result : bool;
    ubi_chain = skein::typedefs::UbiChainBlock::new(1024);

    hash_len = 384;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_1024_0384[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,16);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(1024);
    hash_len = 512;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_1024_0512[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,16);
    assert_eq!(test_result, true);

    ubi_chain = skein::typedefs::UbiChainBlock::new(1024);
    hash_len = 1024;
    skein::process_configuration_block(&mut ubi_chain, 0x33414853, 1,hash_len ,0,0,0);
    test_result = compare_blocks((&CONFIG_1024_1024[0])as *const u64, (&ubi_chain.chain_block[0])
    as *const u64,16);
    assert_eq!(test_result, true);
}

