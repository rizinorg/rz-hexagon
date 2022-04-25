// SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define BIT_MASK(len) (BIT(len)-1)
#define BF_MASK(start, len) (BIT_MASK(len)<<(start))
#define BF_PREP(x, start, len) (((x)&BIT_MASK(len))<<(start))
#define BF_GET(y, start, len) (((y)>>(start)) & BIT_MASK(len))
#define BF_GETB(y, start, end) (BF_GET((y), (start), (end) - (start) + 1)
