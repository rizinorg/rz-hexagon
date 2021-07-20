# SPDX-FileCopyrightText: 2021 Rot127 <unisono@quyllur.org>
#
# SPDX-License-Identifier: LGPL-3.0-only


class UnexpectedException(Exception):
    def __init__(self, message):
        super().__init__(message)
