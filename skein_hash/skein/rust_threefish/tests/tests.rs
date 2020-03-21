extern crate rust_threefish;

const EXPECTED_RESULTS_0256 : [u64;4] = [
    0x94EEEA8B1F2ADA84, 0xADF103313EAE6670, 0x952419A1F4B16D53, 0xD83F13E63C9F6B11];

const EXPECTED_RESULTS_0512 : [u64;8] = [
    0xF10D79B98547CD36, 0xAD359A25818CE2F0, 0xEEC71CD2E09507D9, 0xC9B53E9722BE195C,
    0x86D455E762A50C27, 0xD3E9610FDB35189C, 0x6267C5EF32CA6C2D, 0x1C62FE1A7B6ACD73];

const EXPECTED_RESULTS_1024 : [u64;16]= [
    0x13B5E85CE91B7861, 0x2EB21D247DADF412, 0xF6CE3ABAA911FE25, 0xD86E2D5B49757720,
    0x044A39F23E5851D6, 0x07F937A0B0C5EA02, 0x2186D496A0B2FBDD, 0xFDFECCDBCCBAC03B,
    0x8B00A5C8D1442F3F, 0xD8AD9436799CC0E9, 0x6A31FEBC565F2C24, 0xFDE6194075561BEC,
    0x70E7BA6A9C916FAF, 0x9911EA3A84F5F38A, 0x626211FCD32B984E, 0x1B8E5D87BD779D50];

/***************************************************************************************************
** FUNCTION NAME:  compare_blocks
**
** PURPOSE:        compares two blocks to see if they are the same
**
** ARGUMENTS:      a = the first block
**                 b = the second block
**                 word_count = the number of words to compare in the blocks
**
** RETURN:         true = the blocks are the same
**                 false = the blocks are different
**
** NOTES:          (none)
***************************************************************************************************/
fn compare_blocks(a : *const u64, b : *const u64, word_count : usize) -> bool{
    unsafe {
        for i in 0..word_count{
            if *(((a as u64) + (i*8)as u64)as *const u64) !=
            *(((b as u64) + (i*8)as u64)as *const u64){ return false; }
        }
        return true;
    }
}

/***************************************************************************************************
** FUNCTION NAME:  copy_block
**
** PURPOSE:        copyies one block into another
**
** ARGUMENTS:      from = the block to copy from
**                 to = the block to copy to
**                 word_count = the number of words to compare in the blocks
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn copy_block(from : & rust_threefish::typedefs::Block, to : &mut rust_threefish::typedefs::Block,
word_count : usize){
    for i in 0..word_count{
        to[i] = from[i];
    }
}


#[test]
/***************************************************************************************************
** TEST NAME:      test_block_operations
**
** PURPOSE:        test that the overall algorithm encrypts and decrypts correctly
**
** ARGUMENTS:      (none)
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn test_block_operations(){
    let mut key : rust_threefish::typedefs::Key = [0;17];
    let original_block : rust_threefish::typedefs::Block = [0;16];
    let mut block : rust_threefish::typedefs::Block = [0;16];
    let tweak : rust_threefish::typedefs::Tweak = [0;3];

    let mut test_result : bool;

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 256,256);
    test_result = compare_blocks(&EXPECTED_RESULTS_0256[0], &block[0],4);
    assert_eq!(test_result,true);

    rust_threefish::decrypt_block(&mut block, &mut key, &tweak, 256,256);
    test_result = compare_blocks(&original_block[0], &block[0],4);
    assert_eq!(test_result,true);

    copy_block(&original_block, &mut block,16);

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 512,512);
    test_result = compare_blocks(&EXPECTED_RESULTS_0512[0], &block[0],8);
    assert_eq!(test_result,true);
    rust_threefish::decrypt_block(&mut block, &mut key, &tweak, 512,512);
    test_result = compare_blocks(&original_block[0], &block[0],8);
    assert_eq!(test_result,true);
    copy_block(&original_block, &mut block,16);

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 1024,1024);
    test_result = compare_blocks(&EXPECTED_RESULTS_1024[0], &block[0],16);
    assert_eq!(test_result,true);
    rust_threefish::decrypt_block(&mut block, &mut key, &tweak, 1024,1024);
    test_result = compare_blocks(&original_block[0], &block[0],16);
    assert_eq!(test_result,true);
}

#[test]
/***************************************************************************************************
** TEST NAME:      test_wrong_key
**
** PURPOSE:        test that the wrong keys do not decrypt blocks correctly!
**
** ARGUMENTS:      (none)
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
fn test_wrong_key(){
    let mut key : rust_threefish::typedefs::Key = [0;17];
    let mut wkey : rust_threefish::typedefs::Key = [1;17];

    let original_block : rust_threefish::typedefs::Block = [222;16];
    let mut block : rust_threefish::typedefs::Block = [222;16];
    let tweak : rust_threefish::typedefs::Tweak = [0;3];
    let mut test_result : bool;

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 256,256);
    rust_threefish::decrypt_block(&mut block, &mut wkey, &tweak, 256,256);
    test_result = compare_blocks(&original_block[0], &block[0],4);
    assert_eq!(test_result,false);
    copy_block(&original_block, &mut block,16);

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 512,512);
    rust_threefish::decrypt_block(&mut block, &mut wkey, &tweak, 512,512);
    test_result = compare_blocks(&original_block[0], &block[0],8);
    assert_eq!(test_result,false);
    copy_block(&original_block, &mut block,16);

    rust_threefish::encrypt_block(&mut block, &mut key, &tweak, 1024,1024);
    rust_threefish::decrypt_block(&mut block, &mut wkey, &tweak, 1024,1024);
    test_result = compare_blocks(&original_block[0], &block[0],16);
    assert_eq!(test_result,false);
}
