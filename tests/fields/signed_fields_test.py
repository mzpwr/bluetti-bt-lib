from decimal import Decimal
import struct
import unittest

from bluetti_bt_lib.fields import IntField, SignedDecimalField, FieldName


class TestSignedFields(unittest.TestCase):
    def test_int_field_negative_export(self):
        field = IntField(FieldName.AC_P1_POWER, 1510)
        # 62175 unsigned == -3361 signed 16-bit (live EP760 export capture)
        self.assertEqual(field.parse(struct.pack("!H", 62175)), -3361)
        self.assertTrue(field.in_range(-3361))
        self.assertFalse(field.is_writeable())

    def test_int_field_positive_and_bounds(self):
        field = IntField(FieldName.AC_P1_POWER, 1510, min=-5000, max=5000)
        self.assertEqual(field.parse(struct.pack("!h", 1250)), 1250)
        self.assertFalse(field.in_range(-5001))
        self.assertFalse(field.in_range(5001))

    def test_signed_decimal_field_negative_multiplier(self):
        field = SignedDecimalField(
            FieldName.DC_2_OUTPUT_CURRENT, 15536, 2, multiplier=-1
        )
        self.assertEqual(field.parse(struct.pack("!h", -385)), Decimal("3.85"))
        self.assertEqual(field.parse(struct.pack("!h", 385)), Decimal("-3.85"))
        self.assertFalse(field.is_writeable())
