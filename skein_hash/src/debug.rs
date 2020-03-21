/***************************************************************************************************
** MODULE NAME:    debug
**
** PURPOSE:        useful functions used for debugging in this specific library
**
** PUBLIC CONSTS:  (none)
**
** PUBLIC TYPES:   (none)
**
** PUBLIC FUNCS:   zz_print_message
**
** NOTES:          all functions begin with zz to make it easier to comment out
***************************************************************************************************/

/***************************************************************************************************
** FUNCTION NAME:  zz_print_message
**
** PURPOSE:        prints a debugging message
**
** ARGUMENTS:      message = the message to be printed
**
** RETURN:         void
**
** NOTES:          (none)
***************************************************************************************************/
#[allow(dead_code)]
pub fn zz_print_message(message : &str){
    println!("{}", message);
}
