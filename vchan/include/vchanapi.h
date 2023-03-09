/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef VCHANAPI_H_
#define VCHANAPI_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Header for the aos core messages  over vchan.
 */

#pragma pack(push, 1)
struct VchanMessageHeader
{
    uint32_t dataSize;
    uint8_t sha256[32];
};
#pragma pack(pop)

#endif
