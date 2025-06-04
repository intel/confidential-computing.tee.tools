#!/usr/bin/env python

# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

"""
Enrolling keys and variables into OVMF
"""

import argparse
import logging
from ovmfkeyenroll.var_enroll import var_enroll, VarEnrollOps

# pylint: disable=redefined-builtin

LOG = logging.getLogger(__name__)

class VarEnrollParams:
    """
    VarEnroll related params
    """

    def __init__(
        self,
        info=None,
        input=None,
        operation=None,
        name=None,
        guid=None,
        attributes=None,
        data_file=None,
        output=None,
    ):
        self.info = info
        self.input = input
        self.operation = operation
        self.name = name
        self.guid = guid
        self.attributes = attributes
        self.data_file = data_file
        self.output = output


if __name__ == "__main__":
    LOG.info("Enroll variables into OVMF")

    parser = argparse.ArgumentParser(
        description="The utility to enroll variables into OVMF"
    )

    # add arguments
    parser.add_argument(
        "-i", type=str, default="OVMF.fd", help="Path to OVMF input file", dest="ovmf_input_path"
    )
    parser.add_argument(
        "-o", type=str, default="OVMF_FDE.fd", help="Path to OVMF output file", dest="ovmf_output_path"
    )
    parser.add_argument(
        "-n", type=str, default=None, help="Name of variable to enroll", dest="variable_name", required=True
    )
    parser.add_argument(
        "-g", type=str, default=None, help="GUID of variable to enroll", dest="variable_guid", required=True
    )
    parser.add_argument(
        "-d", type=str, default=None, help="Path for file containing value of variable to enroll", dest="variable_value_file_path", required=True
    )

    # Parse arguments
    args = parser.parse_args()

    # Enroll
    params = VarEnrollParams(
        input=args.ovmf_input_path,
        output=args.ovmf_output_path,
        data_file=args.variable_value_file_path,
        guid=args.variable_guid,
        name=args.variable_name,
        attributes="7",
        operation=VarEnrollOps.ADD,
    )
    if var_enroll(params):
        LOG.info("Variable enrolled successfully")
    else:
        LOG.error("Variable enrolled failed")
