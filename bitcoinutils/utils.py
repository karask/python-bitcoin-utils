# Copyright (C) 2018 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from decimal import Decimal


'''
Converts from any number (int/float) to Decimal with precision 8
'''
def decimal8(num):
    # TODO note that it rounds up to decimal 8 automatically, e.g. for "1.2-1"
    # TODO check if there are cases where rounding a long before converting to
    # decimal would be better
    return Decimal(num).quantize(Decimal('0.00000000'))

