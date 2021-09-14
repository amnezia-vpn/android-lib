#ifndef AMNEZIANL_H
#define AMNEZIANL_H

#include "amnezianl_global.h"
//#include "client/ovpncli.hpp"
//#include "client/ovpncli.cpp"
//#include "openvpn/client/clievent.hpp"

#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <atomic>

#include <openvpn/io/io.hpp>

// Set up export of our public interface unless
// OPENVPN_CORE_API_VISIBILITY_HIDDEN is defined
#if defined(__GNUC__)
#define OPENVPN_CLIENT_EXPORT
#ifndef OPENVPN_CORE_API_VISIBILITY_HIDDEN
#pragma GCC visibility push(default)
#endif
#include "ovpncli.hpp" // public interface
#ifndef OPENVPN_CORE_API_VISIBILITY_HIDDEN
#pragma GCC visibility pop
#endif
#else
// no public interface export defined for this compiler
#define OPENVPN_CLIENT_EXPORT
#include "ovpncli.hpp" // public interface
#endif

// debug settings (production setting in parentheses)

//#define OPENVPN_DUMP_CONFIG          // dump parsed configuration (comment out)
//#define OPENVPN_DEBUG_CLIPROTO       // shows packets in/out (comment out)
#define OPENVPN_DEBUG_PROTO   1        // increases low-level protocol verbosity (1)
//#define OPENVPN_DEBUG_PROTO_DUMP     // dump hex of transport-layer packets, requires OPENVPN_DEBUG_CLIPROTO (comment out)
//#define OPENVPN_DEBUG_VERBOSE_ERRORS // verbosely log Error::Type errors (comment out)
#define OPENVPN_DEBUG_TUN     2        // debug level for tun object (2)
#define OPENVPN_DEBUG_UDPLINK 2        // debug level for UDP link object (2)
#define OPENVPN_DEBUG_TCPLINK 2        // debug level for TCP link object (2)
#define OPENVPN_DEBUG_COMPRESS 1       // debug level for compression objects (1)
#define OPENVPN_DEBUG_REMOTELIST 0     // debug level for RemoteList object (0)
#define OPENVPN_DEBUG_TUN_BUILDER 0    // debug level for tun/builder/client.hpp (0)
//#define OPENVPN_SHOW_SESSION_TOKEN   // show server-pushed auth-token (comment out)
//#define OPENVPN_DEBUG_TAPWIN           // shows Windows TAP driver debug logging (comment out)

// enable assertion checks (can safely be disabled in production)
//#define OPENVPN_ENABLE_ASSERT

// force null tun device (useful for testing)
//#define OPENVPN_FORCE_TUN_NULL

// log cleartext tunnel packets to file for debugging/analysis
//#define OPENVPN_PACKET_LOG "pkt.log"

#ifndef OPENVPN_LOG
// log thread settings
#define OPENVPN_LOG_CLASS openvpn::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO  openvpn::ClientAPI::LogInfo
#include <openvpn/log/logthread.hpp>    // should be included early
#endif

// log SSL handshake messages
#define OPENVPN_LOG_SSL(x) OPENVPN_LOG(x)

// on Android and iOS, use TunBuilderBase abstraction
#include <openvpn/common/platform.hpp>
#if (defined(OPENVPN_PLATFORM_ANDROID) || defined(OPENVPN_PLATFORM_IPHONE)) && !defined(OPENVPN_FORCE_TUN_NULL) && !defined(OPENVPN_EXTERNAL_TUN_FACTORY)
#define USE_TUN_BUILDER
#endif

#include <openvpn/init/initprocess.hpp>
#include <openvpn/common/bigmutex.hpp>
#include <openvpn/common/size.hpp>
#include <openvpn/common/platform_string.hpp>
#include <openvpn/common/count.hpp>
#include <openvpn/asio/asiostop.hpp>
#include <openvpn/time/asiotimer.hpp>
#include <openvpn/client/cliconnect.hpp>
#include <openvpn/client/cliopthelper.hpp>
#include <openvpn/options/merge.hpp>
#include <openvpn/error/excode.hpp>
#include <openvpn/crypto/selftest.hpp>

// copyright
#include <openvpn/legal/copyright.hpp>

namespace openvpn {
  namespace ClientAPI {

    OPENVPN_SIMPLE_EXCEPTION(app_expired);

    class MySessionStats : public SessionStats {
    public:
      typedef RCPtr<MySessionStats> Ptr;

      MySessionStats(OpenVPNClient* parent_arg);

      static size_t combined_n();
      static std::string combined_name(const size_t index);
      count_t combined_value(const size_t index) const;
      count_t stat_count(const size_t index) const;
      count_t error_count(const size_t index) const;
      void detach_from_parent();
      virtual void error(const size_t err, const std::string* text=nullptr);

    private:
      OpenVPNClient* parent;
      count_t errors[Error::N_ERRORS];
    };

    class MyClientEvents : public ClientEvent::Queue {
    public:
      typedef RCPtr<MyClientEvents> Ptr;

      MyClientEvents(OpenVPNClient* parent_arg);

      virtual void add_event(ClientEvent::Base::Ptr event) override;
      void get_connection_info(ConnectionInfo& ci);
      void detach_from_parent();

    private:
      OpenVPNClient* parent;
      ClientEvent::Base::Ptr last_connected;
    };

    class MySocketProtect : public SocketProtect {
    public:
      MySocketProtect();

      void set_parent(OpenVPNClient* parent_arg);
      void set_rg_local(bool rg_local_arg);
      bool socket_protect(int socket, IP::Addr endpoint) override;
      void detach_from_parent();

    private:
      OpenVPNClient* parent;
      bool rg_local = false; // do not add bypass route if true
    };

    class MyReconnectNotify : public ReconnectNotify {
    public:
      MyReconnectNotify();

      void set_parent(OpenVPNClient* parent_arg);
      void detach_from_parent();
      virtual bool pause_on_connection_timeout();

    private:
      OpenVPNClient* parent;
    };

    class MyRemoteOverride : public RemoteList::RemoteOverride {
    public:
      void set_parent(OpenVPNClient* parent_arg);
      void detach_from_parent();
      virtual RemoteList::Item::Ptr get() override;

    private:
      OpenVPNClient* parent = nullptr;
    };

    class MyClockTick {
    public:
      MyClockTick(openvpn_io::io_context& io_context,
          OpenVPNClient* parent_arg, const unsigned int ms);

      void cancel();
      void detach_from_parent();
      void schedule();

    private:
      AsioTimer timer;
      OpenVPNClient* parent;
      const Time::Duration period;
    };

    namespace Private {
      class ClientState
      {
      public:
        // state objects
        OptionList options;
        EvalConfig eval;
        MySocketProtect socket_protect;
        MyReconnectNotify reconnect_notify;
        MyRemoteOverride remote_override;
        ClientCreds::Ptr creds;
        MySessionStats::Ptr stats;
        MyClientEvents::Ptr events;
        ClientConnect::Ptr session;
        std::unique_ptr<MyClockTick> clock_tick;

        // extra settings submitted by API client
        std::string server_override;
        std::string port_override;
        Protocol proto_override;
        IP::Addr::Version proto_version_override;
        IPv6Setting ipv6;
        int conn_timeout = 0;
        bool tun_persist = false;
        bool wintun = false;
        bool google_dns_fallback = false;
        bool synchronous_dns_lookup = false;
        bool autologin_sessions = false;
        bool retry_on_auth_failed = false;
        std::string private_key_password;
        std::string external_pki_alias;
        bool disable_client_cert = false;
        int ssl_debug_level = 0;
        int default_key_direction = -1;
        std::string tls_version_min_override;
        std::string tls_cert_profile_override;
        std::string tls_cipher_list;
        std::string tls_ciphersuite_list;
        std::string gui_version;
        std::string sso_methods;
        bool allow_local_lan_access = false;
        std::string hw_addr_override;
        std::string platform_version;
        ProtoContextOptions::Ptr proto_context_options;
        PeerInfo::Set::Ptr extra_peer_info;
        HTTPProxyTransport::Options::Ptr http_proxy_options;
        unsigned int clock_tick_ms = 0;
    #ifdef OPENVPN_GREMLIN
        Gremlin::Config::Ptr gremlin_config;
    #endif
        bool alt_proxy = false;
        bool dco = true;
        bool echo = false;
        bool info = false;

        // Ensure that init is called
        InitProcess::Init init;

        template <typename SESSION_STATS, typename CLIENT_EVENTS>
        void attach(OpenVPNClient* parent,
                openvpn_io::io_context* io_context,
                Stop* async_stop_global);

        ClientState();
        ~ClientState();

        // foreign thread access

        void enable_foreign_thread_access();
        bool is_foreign_thread_access();

        // io_context
        openvpn_io::io_context* io_context();

        // async stop
        Stop* async_stop_local();
        Stop* async_stop_global();
        void trigger_async_stop_local();

        // disconnect
        void on_disconnect();
        void setup_async_stop_scopes();

          private:
        ClientState(const ClientState&) = delete;
        ClientState& operator=(const ClientState&) = delete;

        bool attach_called = false;

        Stop async_stop_local_;
        Stop* async_stop_global_ = nullptr;

        std::unique_ptr<AsioStopScope> stop_scope_local;
        std::unique_ptr<AsioStopScope> stop_scope_global;

        openvpn_io::io_context* io_context_ = nullptr;
        bool io_context_owned = false;

        std::atomic<bool> foreign_thread_ready{false};
      };
    };

//    OPENVPN_CLIENT_EXPORT /*OpenVPNClient::*/OpenVPNClient();

//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/parse_config(const Config& config, EvalConfig& eval, OptionList& options);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/parse_extras(const Config& config, EvalConfig& eval);
//    OPENVPN_CLIENT_EXPORT long /*OpenVPNClient::*/max_profile_size();
//    OPENVPN_CLIENT_EXPORT MergeConfig /*OpenVPNClient::*/merge_config_static(const std::string& path,
//                                     bool follow_references);
//    OPENVPN_CLIENT_EXPORT MergeConfig /*OpenVPNClient::*/merge_config_string_static(const std::string& config_content);
//    OPENVPN_CLIENT_EXPORT MergeConfig /*OpenVPNClient::*/build_merge_config(const ProfileMerge& pm);
//    OPENVPN_CLIENT_EXPORT EvalConfig /*OpenVPNClient::*/eval_config_static(const Config& config);

//    // API client submits the configuration here before calling connect()
//    OPENVPN_CLIENT_EXPORT EvalConfig /*OpenVPNClient::*/eval_config(const Config& config);
//    OPENVPN_CLIENT_EXPORT Status /*OpenVPNClient::*/provide_creds(const ProvideCreds& creds);
//    OPENVPN_CLIENT_EXPORT bool /*OpenVPNClient::*/socket_protect(int socket, std::string remote, bool ipv6);
//    OPENVPN_CLIENT_EXPORT bool /*OpenVPNClient::*/parse_dynamic_challenge(const std::string& cookie, DynamicChallenge& dc);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/process_epki_cert_chain(const ExternalPKICertRequest& req);
//    OPENVPN_CLIENT_EXPORT Status /*OpenVPNClient::*/connect();
//    OPENVPN_CLIENT_EXPORT Status /*OpenVPNClient::*/do_connect();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/do_connect_async();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/connect_setup(Status& status, bool& session_started);
//    OPENVPN_CLIENT_EXPORT Status /*OpenVPNClient::*/status_from_exception(const std::exception& e);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/connect_attach();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/connect_pre_run();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/connect_run();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/connect_session_stop();
//    OPENVPN_CLIENT_EXPORT ConnectionInfo /*OpenVPNClient::*/connection_info();
//    OPENVPN_CLIENT_EXPORT bool /*OpenVPNClient::*/session_token(SessionToken& tok);
//    OPENVPN_CLIENT_EXPORT Stop* /*OpenVPNClient::*/get_async_stop();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/external_pki_error(const ExternalPKIRequestBase& req, const size_t err_type);
//    OPENVPN_CLIENT_EXPORT bool /*OpenVPNClient::*/sign(const std::string& data, std::string& sig, const std::string& algorithm);
//    OPENVPN_CLIENT_EXPORT bool /*OpenVPNClient::*/remote_override_enabled();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/remote_override(RemoteOverride&);
//    OPENVPN_CLIENT_EXPORT int /*OpenVPNClient::*/stats_n();
//    OPENVPN_CLIENT_EXPORT std::string /*OpenVPNClient::*/stats_name(int index);
//    OPENVPN_CLIENT_EXPORT long long /*OpenVPNClient::*/stats_value(int index) const;
//    OPENVPN_CLIENT_EXPORT std::vector<long long> /*OpenVPNClient::*/stats_bundle() const;
//    OPENVPN_CLIENT_EXPORT InterfaceStats /*OpenVPNClient::*/tun_stats() const;
//    OPENVPN_CLIENT_EXPORT TransportStats /*OpenVPNClient::*/transport_stats() const;
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/stop();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/pause(const std::string& reason);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/resume();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/reconnect(int seconds);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/post_cc_msg(const std::string& msg);
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/clock_tick();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/on_disconnect();
//    OPENVPN_CLIENT_EXPORT std::string /*OpenVPNClient::*/crypto_self_test();
//    OPENVPN_CLIENT_EXPORT int /*OpenVPNClient::*/app_expire();
//    OPENVPN_CLIENT_EXPORT void /*OpenVPNClient::*/check_app_expired();
//    OPENVPN_CLIENT_EXPORT std::string /*OpenVPNClient::*/copyright();
//    OPENVPN_CLIENT_EXPORT std::string /*OpenVPNClient::*/platform();

//    OPENVPN_CLIENT_EXPORT /*OpenVPNClient::*/~OpenVPNClient();
  }
}

class OpenVPNClientAndroid;

class AMNEZIANL_EXPORT Amnezianl
{
public:
    AMNEZIANL_EXPORT Amnezianl();
    AMNEZIANL_EXPORT OpenVPNClientAndroid* getInterfacePointer() const {
        return client;
    }

private:
    OpenVPNClientAndroid* client;
};

class OpenVPNClientAndroid: public openvpn::ClientAPI::OpenVPNClient {
    virtual bool pause_on_connection_timeout();
    virtual void event(const openvpn::ClientAPI::Event &event);
    virtual void log(const openvpn::ClientAPI::LogInfo& loginfo);
    virtual void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& req);
    virtual void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& req);
};

#endif // AMNEZIANL_H
