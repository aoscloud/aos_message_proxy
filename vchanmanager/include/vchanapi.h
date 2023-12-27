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

enum AosVChanSource {
    AOS_VCHAN_SM,
    AOS_VCHAN_IAM,
};

/**
 * Aos core vchan message header.
 */

#pragma pack(push, 1)
struct VChanMessageHeader {
    uint32_t mSource;
    uint32_t mDataSize;
    uint64_t mRequestID;
    int32_t  mErrno;
    int32_t  mAosError;
    char     mMethodName[256];
    uint8_t  mSha256[32];
};
#pragma pack(pop)

#endif
