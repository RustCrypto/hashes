//lots of bit flipping going on in here!

/***************************************************************************************************
** FUNCTION NAME:  set_type
**
** PURPOSE:        sets the type in the tweak value
**
** ARGUMENTS:      original_tweak = (self explanatory)
**                 code = the code value of the type to be used
**
** RETURN:         a u64 value with all the type bits set to the type indicated
**
** NOTES:          (none)
***************************************************************************************************/
pub fn set_type(original_tweak : u64, code : u8)->u64{
    return (original_tweak &
        0b11000000_11111111_11111111_11111111_11111111_11111111_11111111_11111111) |
        ((code as u64) << 56);
}

/***************************************************************************************************
** FUNCTION NAME:  set_pad_on
**
** PURPOSE:        sets the pad flag on
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the pad flag on
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)] //allow bit padding implementations in the future
pub fn set_pad_on(original_tweak : u64)->u64{
    return original_tweak |
    0b00000000_10000000_00000000_00000000_00000000_00000000_00000000_00000000;
}

/***************************************************************************************************
** FUNCTION NAME:  set_pad_off
**
** PURPOSE:        sets the pad flag off
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the pad flag off
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)] //allow bit padding implementations in the future
pub fn set_pad_off(original_tweak : u64)->u64{
    return original_tweak &
    0b11111111_01111111_11111111_11111111_11111111_11111111_11111111_11111111;
}

/***************************************************************************************************
** FUNCTION NAME:  set_first_on
**
** PURPOSE:        sets the first flag on
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the first flag on
**
** NOTES:          (none)
***************************************************************************************************/
pub fn set_first_on(original_tweak : u64)->u64{
    return original_tweak |
    0b01000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000;
}

/***************************************************************************************************
** FUNCTION NAME:  set_first_off
**
** PURPOSE:        sets the first flag off
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the first flag off
**
** NOTES:          (none)
***************************************************************************************************/
pub fn set_first_off(original_tweak : u64)->u64{
    return original_tweak &
    0b10111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111;
}


/***************************************************************************************************
** FUNCTION NAME:  set_last_on
**
** PURPOSE:        sets the last flag on
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the last flag on
**
** NOTES:          (none)
***************************************************************************************************/
pub fn set_last_on(original_tweak : u64)->u64{
    return original_tweak |
    0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000;
}

/***************************************************************************************************
** FUNCTION NAME:  set_last_off
**
** PURPOSE:        sets the last flag off
**
** ARGUMENTS:      original_tweak = (self explanatory)
**
** RETURN:         a u64 value with the last flag off
**
** NOTES:          (none)
***************************************************************************************************/
pub fn set_last_off(original_tweak : u64)->u64{
    return original_tweak &
    0b01111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111;
}

/***************************************************************************************************
** FUNCTION NAME:  set_tree_level
**
** PURPOSE:        sets the tree level up to but not including 128
**
** ARGUMENTS:      original_tweak = (self explanatory)
**                 levels = the levels of recursion that is used
**
** RETURN:         a u64 value with the tree level set to amount desired
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)] //allow for tree hashing implementations in the future
pub fn set_tree_level(original_tweak : u64, levels : usize)->u64{
    if levels < 128{
        return (original_tweak &
        0b11111111_10000000_11111111_11111111_11111111_11111111_11111111_11111111) |
        ((levels as u64) <<48);
    } else {
        panic!("tree size too big");
    }
}
