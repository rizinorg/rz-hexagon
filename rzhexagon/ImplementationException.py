# SPDX-FileCopyrightText: 2021 Rot127 <rot127@posteo.com>
#
# SPDX-License-Identifier: LGPL-3.0-only


class ImplementationException(NotImplementedError):
    def __init__(self, message):
        message = "\n\n" + message + "\nPlease update the implementation to cover this yet unknown" " case."
        super().__init__(message)
