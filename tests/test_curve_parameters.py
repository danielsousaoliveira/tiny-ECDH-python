import numpy as np

import utils


def test_sect163r2_parameters_match_sec2_literals():
    assert utils.CURVE_DEGREE == 163
    assert utils.polynomial == [0x000000C9, 0x00000000, 0x00000000,
                                0x00000000, 0x00000000, 0x00000008]
    assert utils.coeff_a == 1
    assert utils.coeff_b == [0x4A3205FD, 0x512F7874, 0x1481EB10,
                             0xB8C953CA, 0x0A601907, 0x00000002]
    assert utils.base_x == [0xE8343E36, 0xD4994637, 0xA0991168,
                            0x86A2D57E, 0xF0EBA162, 0x00000003]
    assert utils.base_y == [0x797324F1, 0xB11C5C0C, 0xA2CDD545,
                            0x71A0094F, 0xD51FBC6C, 0x00000000]
    assert utils.base_order == [0xA4234C33, 0x77E70C12, 0x000292FE,
                                0x00000000, 0x00000000, 0x00000004]
    assert utils.cofactor == 2

    assert np.array_equal(np.array(utils.base_x, dtype=np.uint32),
                          np.array([0xE8343E36, 0xD4994637, 0xA0991168,
                                    0x86A2D57E, 0xF0EBA162, 0x00000003], dtype=np.uint32))
