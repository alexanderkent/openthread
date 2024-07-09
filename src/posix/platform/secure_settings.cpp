#include "openthread-posix-config.h"
#include "platform-posix.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cinttypes>
#include <cassert>

#include <openthread/platform/logging.h>
#include <openthread/platform/misc.h>
#include <openthread/platform/secure_settings.h>

#include "common/code_utils.hpp"
#include "common/encoding.hpp"
#include "common/settings.hpp"
#include "system.hpp"

static const size_t kMaxFileNameSize = sizeof(OPENTHREAD_CONFIG_POSIX_SETTINGS_PATH) + 32;
static int sSecureSettingsFd = -1;

static void getSecureSettingsFileName(otInstance *aInstance, char aFileName[kMaxFileNameSize], bool aSwap)
{
    const char *offset = getenv("PORT_OFFSET");
    uint64_t    nodeId;

    otPlatRadioGetIeeeEui64(aInstance, reinterpret_cast<uint8_t *>(&nodeId));
    nodeId = ot::BigEndian::HostSwap64(nodeId);
    snprintf(aFileName, kMaxFileNameSize, "%s/secure_%s_%" PRIx64 ".%s",
             OPENTHREAD_CONFIG_POSIX_SETTINGS_PATH, offset == nullptr ? "0" : offset, nodeId, (aSwap ? "swap" : "data"));
}

void otPosixSecureSettingsInit(otInstance *aInstance)
{
    struct stat st;

    if (stat(OPENTHREAD_CONFIG_POSIX_SETTINGS_PATH, &st) == -1)
    {
        VerifyOrDie(mkdir(OPENTHREAD_CONFIG_POSIX_SETTINGS_PATH, 0755) == 0, OT_EXIT_ERROR_ERRNO);
    }

    char fileName[kMaxFileNameSize];
    getSecureSettingsFileName(aInstance, fileName, false);
    sSecureSettingsFd = open(fileName, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    VerifyOrDie(sSecureSettingsFd != -1, OT_EXIT_ERROR_ERRNO);

    for (off_t size = lseek(sSecureSettingsFd, 0, SEEK_END), offset = lseek(sSecureSettingsFd, 0, SEEK_SET); offset < size;)
    {
        uint16_t key;
        uint16_t length;
        ssize_t  rval;

        rval = read(sSecureSettingsFd, &key, sizeof(key));
        VerifyOrExit(rval == sizeof(key));

        rval = read(sSecureSettingsFd, &length, sizeof(length));
        VerifyOrExit(rval == sizeof(length));

        offset += sizeof(key) + sizeof(length) + length;
        VerifyOrExit(offset == lseek(sSecureSettingsFd, length, SEEK_CUR));
    }

exit:
    return;
}

void otPosixSecureSettingsDeinit(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);

    if (sSecureSettingsFd != -1)
    {
        close(sSecureSettingsFd);
        sSecureSettingsFd = -1;
    }
}

otError otPosixSecureSettingsGet(otInstance *aInstance,
                                 uint16_t    aKey,
                                 int         aIndex,
                                 uint8_t    *aValue,
                                 uint16_t   *aValueLength)
{
    OT_UNUSED_VARIABLE(aInstance);

    otError     error = OT_ERROR_NOT_FOUND;
    const off_t size  = lseek(sSecureSettingsFd, 0, SEEK_END);
    off_t       offset = lseek(sSecureSettingsFd, 0, SEEK_SET);

    while (offset < size)
    {
        uint16_t key;
        uint16_t length;
        ssize_t  rval;

        rval = read(sSecureSettingsFd, &key, sizeof(key));
        VerifyOrExit(rval == sizeof(key));

        rval = read(sSecureSettingsFd, &length, sizeof(length));
        VerifyOrExit(rval == sizeof(length));

        if (key == aKey)
        {
            if (aIndex == 0)
            {
                error = OT_ERROR_NONE;

                if (aValueLength)
                {
                    if (aValue)
                    {
                        uint16_t readLength = (length <= *aValueLength ? length : *aValueLength);

                        VerifyOrExit(read(sSecureSettingsFd, aValue, readLength) == readLength);
                    }

                    *aValueLength = length;
                }

                break;
            }
            else
            {
                --aIndex;
            }
        }

        offset += sizeof(key) + sizeof(length) + length;
        VerifyOrExit(offset == lseek(sSecureSettingsFd, length, SEEK_CUR));
    }

exit:
    return error;
}

otError otPosixSecureSettingsSet(otInstance *aInstance, uint16_t aKey, const uint8_t *aValue, uint16_t aValueLength)
{
    int swapFd = -1;

    switch (otPosixSecureSettingsDelete(aInstance, aKey, -1))
    {
    case OT_ERROR_NONE:
    case OT_ERROR_NOT_FOUND:
        break;

    default:
        assert(false);
        break;
    }

    swapFd = open("/tmp/swap", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    VerifyOrDie(swapFd != -1, OT_EXIT_ERROR_ERRNO);

    VerifyOrDie(write(swapFd, &aKey, sizeof(aKey)) == sizeof(aKey) &&
                    write(swapFd, &aValueLength, sizeof(aValueLength)) == sizeof(aValueLength) &&
                    write(swapFd, aValue, aValueLength) == aValueLength,
                OT_EXIT_FAILURE);

    fsync(swapFd);
    close(swapFd);

    // Rename swap file to the secure settings file
    char fileName[kMaxFileNameSize];
    getSecureSettingsFileName(aInstance, fileName, false);
    rename("/tmp/swap", fileName);

    return OT_ERROR_NONE;
}

otError otPosixSecureSettingsAdd(otInstance *aInstance, uint16_t aKey, const uint8_t *aValue, uint16_t aValueLength)
{
    return otPosixSecureSettingsSet(aInstance, aKey, aValue, aValueLength);
}

otError otPosixSecureSettingsDelete(otInstance *aInstance, uint16_t aKey, int aIndex)
{
    OT_UNUSED_VARIABLE(aInstance);

    otError error = OT_ERROR_NOT_FOUND;
    int swapFd    = open("/tmp/swap", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    VerifyOrDie(swapFd != -1, OT_EXIT_ERROR_ERRNO);

    const off_t size  = lseek(sSecureSettingsFd, 0, SEEK_END);
    off_t       offset = lseek(sSecureSettingsFd, 0, SEEK_SET);

    while (offset < size)
    {
        uint16_t key;
        uint16_t length;
        ssize_t  rval;

        rval = read(sSecureSettingsFd, &key, sizeof(key));
        VerifyOrExit(rval == sizeof(key));

        rval = read(sSecureSettingsFd, &length, sizeof(length));
        VerifyOrExit(rval == sizeof(length));

        offset += sizeof(key) + sizeof(length) + length;

        if (aKey == key)
        {
            if (aIndex == 0)
            {
                VerifyOrExit(offset == lseek(sSecureSettingsFd, length, SEEK_CUR));
                error = OT_ERROR_NONE;
                continue;
            }
            else if (aIndex == -1)
            {
                VerifyOrExit(offset == lseek(sSecureSettingsFd, length, SEEK_CUR));
                error = OT_ERROR_NONE;
                continue;
            }
            else
            {
                --aIndex;
            }
        }

        rval = write(swapFd, &key, sizeof(key));
        VerifyOrExit(rval == sizeof(key));

        rval = write(swapFd, &length, sizeof(length));
        VerifyOrExit(rval == sizeof(length));

        uint8_t buffer[512];
        while (length > 0)
        {
            uint16_t count = length >= sizeof(buffer) ? sizeof(buffer) : length;
            rval = read(sSecureSettingsFd, buffer, count);
            VerifyOrExit(rval > 0);

            rval = write(swapFd, buffer, count);
            VerifyOrExit(rval == count);

            length -= count;
        }
    }

    fsync(swapFd);
    close(swapFd);

    // Rename swap file to the secure settings file
    char fileName[kMaxFileNameSize];
    getSecureSettingsFileName(aInstance, fileName, false);
    rename("/tmp/swap", fileName);

exit:
    return error;
}

void otPosixSecureSettingsWipe(otInstance *aInstance)
{
    OT_UNUSED_VARIABLE(aInstance);

    char fileName[kMaxFileNameSize];
    getSecureSettingsFileName(aInstance, fileName, false);
    unlink(fileName);
}
