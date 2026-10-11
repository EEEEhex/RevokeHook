#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace revokehook
{
    // Verified on Weixin 4.1.15.50: the first byte flag is argument 5.
    // The window ends with a complete E8 rel32 call; its displacement may vary.
    constexpr std::size_t kAdd2DbCallPrefixSize = 13;
    constexpr std::size_t kAdd2DbCallWindowSize = kAdd2DbCallPrefixSize + 5;
    constexpr std::size_t kAdd2DbInsertFlagStackOffset = 0x20;

    inline bool MatchesKnownAdd2DbCall(const std::uint8_t* window, std::size_t size)
    {
        static const std::uint8_t expected[] = {
            0xC6, 0x44, 0x24, 0x28, 0x01, // mov byte ptr [rsp+28h], 1
            0xC6, 0x44, 0x24, 0x20, 0x00, // mov byte ptr [rsp+20h], 0
            0x48, 0x89, 0xF2,             // mov rdx, rsi
            0xE8                          // call rel32
        };
        return window != nullptr && size >= kAdd2DbCallWindowSize &&
            std::memcmp(window, expected, sizeof(expected)) == 0;
    }

    // caller_stack is the saved RSP before CALL, not the callee's entry RSP.
    // The caller must verify that the target byte is writable.
    inline bool WriteAdd2DbInsertFlag(bool known_call, std::uint8_t* caller_stack,
        std::size_t stack_size)
    {
        if (!known_call || caller_stack == nullptr ||
            stack_size <= kAdd2DbInsertFlagStackOffset)
            return false;

        caller_stack[kAdd2DbInsertFlagStackOffset] = 1;
        return true;
    }
}
