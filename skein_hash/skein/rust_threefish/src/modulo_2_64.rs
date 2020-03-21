/***************************************************************************************************
** MODULE NAME:    modulo_2_64
**
** PURPOSE:        handles addition and subtraction in modulo_2_64
**
** PUBLIC CONSTS:  (none)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   add -> u64, minus -> u64
**
** NOTES:          (none)
***************************************************************************************************/

/***************************************************************************************************
** FUNCTION NAME:  add
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      a = first word
**                 b = second word
**
** RETURN:         sum
**
** NOTES:          this is done in modulo 18446744073709551616
***************************************************************************************************/
pub fn add(a : u64, b : u64) -> u64 {
    let max_diff : u64 = 18446744073709551615 - a;
    if b <= max_diff{
        return a + b;
    } else {
        return b - max_diff - 1;
    }
}

/***************************************************************************************************
** FUNCTION NAME:  minus
**
** PURPOSE:        (self explanatory)
**
** ARGUMENTS:      a = first word
**                 b = second word
**
** RETURN:         subtraction
**
** NOTES:          this is done in modulo 18446744073709551616
***************************************************************************************************/
pub fn minus(a : u64, b : u64) -> u64 {
    if a >= b{
        return a - b;
    } else {
        return 18446744073709551615 - b + a + 1;
    }
}


/***************************************************************************************************
** TEST NAME:      test_modulo_addition
**
** PURPOSE:        test that the implementation for modulo addition is correct
**
** ARGUMENTS:      (none)
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[test]
fn test_modulo_addition() {
    let mut a : u64 = 18446744073709551615;
    let mut b : u64 = 100;
    let mut expected_result : u64 = 99;
    let mut actual_result :u64 = add(a,b);
    assert_eq!(actual_result,expected_result);

    a = 18446744073709551615;
    b = 1;
    expected_result = 0;
    actual_result = add(a,b);
    assert_eq!(actual_result,expected_result);

    a = 1;
    b = 1;
    expected_result = 2;
    actual_result = add(a,b);
    assert_eq!(actual_result,expected_result);

    a = 18446744073709551614;
    b = 1;
    expected_result  = 18446744073709551615;
    actual_result = add(a,b);
    assert_eq!(actual_result,expected_result);
}

/***************************************************************************************************
** TEST NAME:      test_modulo_subtraction
**
** PURPOSE:        test that the implementation for modulo subtraction is correct
**
** ARGUMENTS:      (none)
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[test]
fn test_modulo_subtraction(){
    let mut a : u64 = 94;
    let mut b : u64 = 100;
    let mut expected_result : u64 = 18446744073709551610;
    let mut actual_result : u64 = minus(a,b);
    assert_eq!(actual_result,expected_result);

    a = 0;
    b = 1;
    expected_result  = 18446744073709551615;
    actual_result  = minus(a,b);
    assert_eq!(actual_result,expected_result);

    a = 1;
    b = 1;
    expected_result  = 0;
    actual_result  = minus(a,b);
    assert_eq!(actual_result,expected_result);

    a = 100;
    b = 50;
    expected_result = 50;
    actual_result  = minus(a,b);
    assert_eq!(actual_result,expected_result);
}
