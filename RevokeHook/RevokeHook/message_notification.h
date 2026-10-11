#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

namespace revokehook
{
    // This profile is restricted to the inspected Weixin 4.1.15.50 image.
    constexpr std::uint32_t kNotifyImageTimestamp = 0x6AB4F57F;
    constexpr std::uint32_t kNotifyImageSize = 0x0C31C000;
    constexpr std::uint32_t kNotifyDeleteCallRva = 0x023BAB8A;
    constexpr std::uint32_t kNotifyAddCallRva = 0x039B4FD8;
    constexpr std::uint32_t kNotifyDeleteWindowRva = 0x023BAB7C;
    constexpr std::uint32_t kNotifyPostWindowRva = 0x023BAC41;
    constexpr std::uint32_t kNotifyPostRva = 0x023BAC6F;
    constexpr std::uint32_t kNotifySignalRva = 0x017CAC20;
    constexpr std::uint32_t kNotifyWorkerWindowRva = 0x039827F6;
    constexpr std::uint32_t kNotifyWorkerResultRva = 0x0398280C;
    constexpr std::size_t kNotifyFrameMessageOffset = 0x2B8;
    constexpr std::size_t kNotifyFrameManagerOffset = 0x9C0;
    constexpr std::size_t kNotifyWorkerFrameMessageOffset = 0x58;
    constexpr std::size_t kNotifySignalOffset = 0xE8;
    constexpr std::size_t kNotifyMessageSize = 0x2E8;
    constexpr std::size_t kNotifyLocalIdOffset = 0x144;
    constexpr std::size_t kNotifySrvIdOffset = 0x148;
    constexpr std::size_t kNotifyMessageTypeOffset = 0x0C;
    constexpr std::uint32_t kNotifySystemMessageType = 10000;

    constexpr std::uint8_t kNotifyDeleteBytes[] = {
        0x48, 0x8B, 0x8D, 0xA0, 0x05, 0x00, 0x00,
        0x48, 0x8D, 0x55, 0xC8, 0x45, 0x31, 0xC0,
        0xE8, 0x91, 0x9E, 0x42, 0xFF
    };
    constexpr std::uint8_t kNotifyAddBytes[] = {
        0xC6, 0x44, 0x24, 0x28, 0x01, 0xC6, 0x44, 0x24, 0x20, 0x00,
        0x48, 0x89, 0xF2, 0xE8, 0xB3, 0xDE, 0xF2, 0xFF
    };
    constexpr std::uint8_t kNotifyPostBytes[] = {
        0x48, 0x8B, 0x8D, 0xC0, 0x09, 0x00, 0x00,
        0x48, 0x8D, 0x95, 0xA0, 0x05, 0x00, 0x00,
        0x4C, 0x8D, 0x85, 0xB8, 0x02, 0x00, 0x00,
        0xE8, 0x55, 0x95, 0x46, 0xFF, 0x90,
        0x48, 0x8D, 0x8D, 0xB8, 0x02, 0x00, 0x00,
        0x48, 0x8D, 0x95, 0xA0, 0x05, 0x00, 0x00,
        0xE8, 0x21, 0x86, 0x1E, 0xFF, 0x90
    };
    constexpr std::uint8_t kNotifySignalBytes[] = {
        0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0xC8, 0x01, 0x00, 0x00,
        0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00,
        0x0F, 0x29, 0xB5, 0x30, 0x01
    };
    constexpr std::uint8_t kNotifyWorkerBytes[] = {
        0x48, 0x8B, 0x8D, 0x30, 0x03, 0x00, 0x00,
        0x48, 0x8D, 0x55, 0xA8, 0x49, 0x89, 0xF8, 0x41, 0x89, 0xD9,
        0xE8, 0x94, 0x67, 0xBD, 0xFD, 0x90, 0x88, 0xC3
    };

    struct NotificationBytes
    {
        const std::uint8_t* data;
        std::size_t size;
    };

    struct NotificationProfileView
    {
        std::uint32_t timestamp;
        std::uint32_t image_size;
        std::uint64_t delete_call_rva;
        std::uint64_t add_call_rva;
        NotificationBytes delete_call;
        NotificationBytes add_call;
        NotificationBytes post_call;
        NotificationBytes signal_entry;
        NotificationBytes worker_result;
    };

    template<std::size_t Size>
    inline bool MatchesNotificationBytes(NotificationBytes actual,
        const std::uint8_t (&expected)[Size])
    {
        return actual.data != nullptr && actual.size == Size &&
            std::memcmp(actual.data, expected, Size) == 0;
    }

    inline bool MatchesNotificationProfile(const NotificationProfileView& profile)
    {
        return profile.timestamp == kNotifyImageTimestamp &&
            profile.image_size == kNotifyImageSize &&
            profile.delete_call_rva == kNotifyDeleteCallRva &&
            profile.add_call_rva == kNotifyAddCallRva &&
            MatchesNotificationBytes(profile.delete_call, kNotifyDeleteBytes) &&
            MatchesNotificationBytes(profile.add_call, kNotifyAddBytes) &&
            MatchesNotificationBytes(profile.post_call, kNotifyPostBytes) &&
            MatchesNotificationBytes(profile.signal_entry, kNotifySignalBytes) &&
            MatchesNotificationBytes(profile.worker_result, kNotifyWorkerBytes);
    }

    // Pure POD storage: a short external lock protects the table operations.
    struct PendingNotification
    {
        std::uintptr_t manager;
        std::uintptr_t owner_rbp;
        std::uintptr_t owner_rsp;
        std::uintptr_t expected_message;
        std::uint32_t previous_local_id;
        std::uint32_t committed_local_id;
        std::uint8_t random_srvid[8];
        std::uint64_t captured_tick;
        std::uint64_t generation;
        bool captured;
        bool armed;
        bool commit_observed;
        bool commit_success;
    };

    constexpr std::size_t kPendingNotificationCapacity = 128;
    constexpr std::uint64_t kPendingNotificationTtlMs = 30000;

    struct PendingNotificationTable
    {
        PendingNotification entries[kPendingNotificationCapacity];
        std::uint64_t next_generation;
    };

    enum class CaptureNotificationResult { Captured, Invalid, Full };
    enum class CommitNotificationResult { Recorded, NoMatch, Ambiguous };

    struct NotificationRequest
    {
        std::uintptr_t manager;
        std::uintptr_t message;
        std::uint32_t previous_local_id;
        std::uint32_t committed_local_id;
        std::uint8_t random_srvid[8];
        bool commit_observed;
        bool commit_success;
    };

    // Release x64 vector layout. This view never owns or destroys the message.
    struct MessageVectorView
    {
        const void* begin;
        const void* end;
        const void* capacity;
    };

    static_assert(std::is_trivial<PendingNotification>::value,
        "PendingNotification must remain trivial");
    static_assert(std::is_trivial<PendingNotificationTable>::value,
        "PendingNotificationTable must remain trivial");
    static_assert(std::is_standard_layout<MessageVectorView>::value &&
        sizeof(MessageVectorView) == 3 * sizeof(void*), "Unexpected vector view layout");

    inline void ClearPendingNotification(PendingNotification& pending)
    {
        pending = {};
    }

    inline void ExpirePendingNotifications(PendingNotificationTable& table,
        std::uint64_t now)
    {
        for (auto& entry : table.entries)
            if (entry.captured && now - entry.captured_tick >= kPendingNotificationTtlMs)
                ClearPendingNotification(entry);
    }

    inline void ClearNotificationFrame(PendingNotificationTable& table,
        std::uintptr_t rbp, std::uintptr_t rsp)
    {
        for (auto& entry : table.entries)
            if (entry.captured && entry.owner_rbp == rbp && entry.owner_rsp == rsp)
                ClearPendingNotification(entry);
    }

    inline CaptureNotificationResult CapturePendingNotification(PendingNotificationTable& table,
        std::uintptr_t manager, std::uintptr_t rbp, std::uintptr_t rsp, std::uint64_t now)
    {
        ExpirePendingNotifications(table, now);
        ClearNotificationFrame(table, rbp, rsp);
        const auto maximum = (std::numeric_limits<std::uintptr_t>::max)();
        if (manager == 0 || rbp == 0 || rsp == 0 ||
            manager > maximum - kNotifySignalOffset ||
            rbp > maximum - kNotifyFrameMessageOffset - kNotifyMessageSize)
            return CaptureNotificationResult::Invalid;

        PendingNotification* available = nullptr;
        const auto expected_message = rbp + kNotifyFrameMessageOffset;
        for (auto& entry : table.entries)
        {
            // Add2DB supplies only the message pointer, so ambiguity must fail closed.
            if (entry.captured && entry.expected_message == expected_message)
                return CaptureNotificationResult::Invalid;
            if (!entry.captured && available == nullptr)
                available = &entry;
        }
        if (available == nullptr)
            return CaptureNotificationResult::Full;

        if (++table.next_generation == 0)
            ++table.next_generation;
        available->manager = manager;
        available->owner_rbp = rbp;
        available->owner_rsp = rsp;
        available->expected_message = expected_message;
        available->captured_tick = now;
        available->generation = table.next_generation;
        available->captured = true;
        return CaptureNotificationResult::Captured;
    }

    inline bool FindPendingNotification(PendingNotificationTable& table,
        std::uintptr_t message, std::uint64_t now, PendingNotification& snapshot)
    {
        ExpirePendingNotifications(table, now);
        snapshot = {};
        for (const auto& entry : table.entries)
            if (entry.captured && entry.expected_message == message)
            {
                snapshot = entry;
                return true;
            }
        return false;
    }

    inline bool ArmPendingNotification(PendingNotificationTable& table,
        const PendingNotification& snapshot, std::uint32_t previous_local_id,
        std::size_t srvid_offset, const std::uint8_t* random_srvid, std::uint64_t now)
    {
        ExpirePendingNotifications(table, now);
        if (srvid_offset != kNotifySrvIdOffset || random_srvid == nullptr)
            return false;
        for (auto& entry : table.entries)
            if (snapshot.captured && entry.captured && !entry.armed &&
                entry.generation == snapshot.generation &&
                entry.expected_message == snapshot.expected_message &&
                entry.owner_rbp == snapshot.owner_rbp && entry.owner_rsp == snapshot.owner_rsp)
            {
                entry.previous_local_id = previous_local_id;
                std::memcpy(entry.random_srvid, random_srvid, sizeof(entry.random_srvid));
                entry.armed = true;
                return true;
            }
        return false;
    }

    // Inputs are copied by the caller before taking the table lock.
    inline CommitNotificationResult RecordNotificationCommit(PendingNotificationTable& table,
        const std::uint8_t* random_srvid, bool succeeded, std::uint32_t local_id,
        std::uint64_t now)
    {
        ExpirePendingNotifications(table, now);
        if (random_srvid == nullptr)
            return CommitNotificationResult::NoMatch;
        PendingNotification* matching = nullptr;
        std::size_t count = 0;
        for (auto& entry : table.entries)
            if (entry.captured && entry.armed &&
                std::memcmp(entry.random_srvid, random_srvid, sizeof(entry.random_srvid)) == 0)
            {
                matching = &entry;
                ++count;
            }
        if (count == 0)
            return CommitNotificationResult::NoMatch;
        if (count != 1)
        {
            // Do not leave an earlier success authorized after a token collision.
            for (auto& entry : table.entries)
                if (entry.captured && entry.armed &&
                    std::memcmp(entry.random_srvid, random_srvid, sizeof(entry.random_srvid)) == 0)
                {
                    entry.commit_observed = true;
                    entry.commit_success = false;
                    entry.committed_local_id = 0;
                }
            return CommitNotificationResult::Ambiguous;
        }
        const bool already_failed = matching->commit_observed && !matching->commit_success;
        matching->commit_observed = true;
        matching->commit_success = succeeded && !already_failed;
        matching->committed_local_id = local_id;
        return CommitNotificationResult::Recorded;
    }

    // Consume only the matching frame, before target reads or subscriber calls.
    inline bool TakePendingNotification(PendingNotificationTable& table,
        std::uintptr_t rbp, std::uintptr_t rsp, std::uint64_t now,
        NotificationRequest& request)
    {
        ExpirePendingNotifications(table, now);
        request = {};
        for (auto& entry : table.entries)
            if (entry.captured && entry.owner_rbp == rbp && entry.owner_rsp == rsp)
            {
                const auto saved = entry;
                ClearPendingNotification(entry);
                if (!saved.armed || saved.manager == 0 ||
                    saved.expected_message != rbp + kNotifyFrameMessageOffset)
                    return false;

                request.manager = saved.manager;
                request.message = saved.expected_message;
                request.previous_local_id = saved.previous_local_id;
                request.committed_local_id = saved.committed_local_id;
                std::memcpy(request.random_srvid, saved.random_srvid, sizeof(request.random_srvid));
                request.commit_observed = saved.commit_observed;
                request.commit_success = saved.commit_success;
                return true;
            }
        return false;
    }

    inline bool IsStoredRevokeNotification(const NotificationRequest& request,
        std::uint32_t local_id, std::uint32_t message_type, bool has_revoke_xml,
        const std::uint8_t* random_srvid)
    {
        return request.manager != 0 && request.message != 0 && local_id != 0 &&
            local_id != request.previous_local_id &&
            request.commit_observed && request.commit_success &&
            request.committed_local_id == local_id &&
            message_type == kNotifySystemMessageType && has_revoke_xml &&
            random_srvid != nullptr &&
            std::memcmp(request.random_srvid, random_srvid, sizeof(request.random_srvid)) == 0;
    }

    inline bool MatchesNotificationManager(const NotificationRequest& request,
        std::uintptr_t current_manager)
    {
        return current_manager != 0 && current_manager == request.manager;
    }

    inline bool BuildMessageVectorView(std::uintptr_t message, MessageVectorView& view)
    {
        view = {};
        if (message == 0 ||
            message > (std::numeric_limits<std::uintptr_t>::max)() - kNotifyMessageSize)
            return false;

        view.begin = reinterpret_cast<const void*>(message);
        view.end = reinterpret_cast<const void*>(message + kNotifyMessageSize);
        view.capacity = view.end;
        return true;
    }

    inline bool ContainsRevokeXml(const char* text, std::size_t size)
    {
        // Accept an XML revocation element or an explicit sysmsg type attribute.
        static const char* const markers[] = {
            "<revokemsg>", "<revokemsg ", "type=\"revokemsg\"", "type='revokemsg'"
        };
        if (text == nullptr || size == 0 || size > 0x10000)
            return false;
        for (const auto* marker : markers)
        {
            const auto length = std::strlen(marker);
            for (std::size_t index = 0; index + length <= size; ++index)
                if (std::memcmp(text + index, marker, length) == 0)
                    return true;
        }
        return false;
    }
}
