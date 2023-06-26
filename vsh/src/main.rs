mod vsh;

fn main() {
    let bytes: Vec<u8> = vec![
        128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 255
    ];

    let mut vhs_x:Vec<usize> = vec![];
    match vsh::validate_and_pad_input(bytes) {
        Ok(result) => {
            // println!("Res;: {:?}", result);
            vhs_x = vsh::calculate_vhs_of_x(result);
        }
        Err(error) => println!("Error: {}", error),
    }
    let primes = vsh::get_prime_list(vhs_x);
    // println!("Prime prod:{:?}",primes);
    vsh::do_mod_with_products(primes);
}
