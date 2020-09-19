// parameters of FSB, hardcoded for each output length
const NUMBER_OF_PARAMETERS: usize = 6;
///
/// parameters of FSB in order:
/// [hashbitlen, n, w, r, p, s
/// In the oficial implementation they compute s on the go. It is constant, so we define it as a
/// parameter.
///
const PARAMETERS: [[u32; 6]; NUMBER_OF_PARAMETERS] = [
    [48, 3<<17, 24, 192, 197, 336],
    [160, 5<<18, 80, 640, 653, 1120],
    [224, 7<<18, 112, 896, 907, 1568],
    [256, 1<<21, 1<<7, 1<<10, 1061, 1792],
    [384, 23<<16, 184, 1472, 1483, 2392],
    [512, 31<<16, 248, 1984, 1987, 3224]
];


