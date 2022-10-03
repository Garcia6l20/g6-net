#include <g6/io/context.hpp>
#include <g6/net/async_socket.hpp>
#include <g6/scope_guard.hpp>

namespace g6::io {

#if G6_OS_WINDOWS
    void ensure_winsock_initialized() {
        if (!context::winsock_initialized) {
            WSADATA wsaData;

            // Initialize Winsock
            auto iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (iResult != 0) { throw std::system_error{static_cast<int>(GetLastError()), std::system_category()}; }
            context::winsock_initialized = true;
        }
    }

    std::tuple<SOCKET, bool> create_socket(net::socket_protocol type, HANDLE ioCompletionPort) {
        // Enumerate available protocol providers for the specified socket type.
        ensure_winsock_initialized();

        WSAPROTOCOL_INFOW stackInfos[4];
        std::unique_ptr<WSAPROTOCOL_INFOW[]> heapInfos;
        WSAPROTOCOL_INFOW *selectedProtocolInfo = nullptr;

        {
            INT protocols[] = {type.proto, 0};
            DWORD bufferSize = sizeof(stackInfos);
            WSAPROTOCOL_INFOW *infos = stackInfos;

            int protocolCount = ::WSAEnumProtocolsW(protocols, infos, &bufferSize);
            if (protocolCount == SOCKET_ERROR) {
                int errorCode = ::WSAGetLastError();
                if (errorCode == WSAENOBUFS) {
                    DWORD requiredElementCount = bufferSize / sizeof(WSAPROTOCOL_INFOW);
                    heapInfos = std::make_unique<WSAPROTOCOL_INFOW[]>(requiredElementCount);
                    bufferSize = requiredElementCount * sizeof(WSAPROTOCOL_INFOW);
                    infos = heapInfos.get();
                    protocolCount = ::WSAEnumProtocolsW(protocols, infos, &bufferSize);
                    if (protocolCount == SOCKET_ERROR) { errorCode = ::WSAGetLastError(); }
                }

                if (protocolCount == SOCKET_ERROR) {
                    throw std::system_error(errorCode, std::system_category(),
                                            "Error creating socket: WSAEnumProtocolsW");
                }
            }

            if (protocolCount == 0) {
                throw std::system_error(std::make_error_code(std::errc::protocol_not_supported));
            }

            for (int i = 0; i < protocolCount; ++i) {
                auto &info = infos[i];
                if (info.iAddressFamily == type.domain && info.iProtocol == type.proto
                    && info.iSocketType == type.type) {
                    selectedProtocolInfo = &info;
                    break;
                }
            }

            if (selectedProtocolInfo == nullptr) {
                throw std::system_error(std::make_error_code(std::errc::address_family_not_supported));
            }
        }

        // WSA_FLAG_NO_HANDLE_INHERIT for SDKs earlier than Windows 7.
        constexpr DWORD flagNoInherit = 0x80;

        const DWORD flags = WSA_FLAG_OVERLAPPED | flagNoInherit;

        const SOCKET socketHandle = ::WSASocketW(type.domain, type.type, type.proto, selectedProtocolInfo, 0, flags);
        if (socketHandle == INVALID_SOCKET) {
            const int errorCode = ::WSAGetLastError();
            throw std::system_error(errorCode, std::system_category(), "Error creating socket: WSASocketW");
        }

        auto closeSocketOnFailure = scope_guard{[&] { ::closesocket(socketHandle); }};

        // This is needed on operating systems earlier than Windows 7 to prevent
        // socket handles from being inherited. On Windows 7 or later this is
        // redundant as the WSA_FLAG_NO_HANDLE_INHERIT flag passed to creation
        // above causes the socket to be atomically created with this flag cleared.
        if (!::SetHandleInformation((HANDLE) socketHandle, HANDLE_FLAG_INHERIT, 0)) {
            const DWORD errorCode = ::GetLastError();
            throw std::system_error(errorCode, std::system_category(), "Error creating socket: SetHandleInformation");
        }

        // Associate the socket with the I/O completion port.
        {
            const HANDLE result =
                ::CreateIoCompletionPort((HANDLE) socketHandle, ioCompletionPort, ULONG_PTR(0), DWORD(0));
            if (result == nullptr) {
                const DWORD errorCode = ::GetLastError();
                throw std::system_error(static_cast<int>(errorCode), std::system_category(),
                                        "Error creating socket: CreateIoCompletionPort");
            }
        }

        const bool skipCompletionPortOnSuccess = (selectedProtocolInfo->dwServiceFlags1 & XP1_IFS_HANDLES) != 0;

        {
            UCHAR completionModeFlags = FILE_SKIP_SET_EVENT_ON_HANDLE;
            if (skipCompletionPortOnSuccess) { completionModeFlags |= FILE_SKIP_COMPLETION_PORT_ON_SUCCESS; }

            const BOOL ok = ::SetFileCompletionNotificationModes((HANDLE) socketHandle, completionModeFlags);
            if (!ok) {
                const DWORD errorCode = ::GetLastError();
                throw std::system_error(static_cast<int>(errorCode), std::system_category(),
                                        "Error creating socket: SetFileCompletionNotificationModes");
            }
        }

        if (type.type == SOCK_STREAM) {
            // Turn off linger so that the destructor doesn't block while closing
            // the socket or silently continue to flush remaining data in the
            // background after ::closesocket() is called, which could fail and
            // we'd never know about it.
            // We expect clients to call Disconnect() or use CloseSend() to cleanly
            // shut-down connections instead.
            BOOL value = TRUE;
            const int result = ::setsockopt(socketHandle, SOL_SOCKET, SO_DONTLINGER,
                                            reinterpret_cast<const char *>(&value), sizeof(value));
            if (result == SOCKET_ERROR) {
                const int errorCode = ::WSAGetLastError();
                throw std::system_error(errorCode, std::system_category(),
                                        "Error creating socket: setsockopt(SO_DONTLINGER)");
            }
        }

        closeSocketOnFailure.disable();

        return std::make_tuple(socketHandle, skipCompletionPortOnSuccess);
    }
#else
    int create_socket(net::socket_protocol type) {
        return ::socket(type.domain, type.type, type.proto);
    }
#endif

}// namespace g6::io