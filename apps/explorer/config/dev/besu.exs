import Config

~w(config config_helper.exs)
|> Path.join()
|> Code.eval_file()

hackney_opts = ConfigHelper.hackney_options()
timeout = ConfigHelper.timeout(1)

config :explorer,
  json_rpc_named_arguments: [
    transport: EthereumJSONRPC.HTTP,
    transport_options: [
      http: EthereumJSONRPC.HTTP.HTTPoison,
      url: System.get_env("ETHEREUM_JSONRPC_HTTP_URL") || "http://0.0.0.0:12001",
      fallback_url: System.get_env("ETHEREUM_JSONRPC_FALLBACK_HTTP_URL"),
      fallback_trace_url: System.get_env("ETHEREUM_JSONRPC_FALLBACK_TRACE_URL"),
      fallback_eth_call_url: System.get_env("ETHEREUM_JSONRPC_FALLBACK_ETH_CALL_URL"),
      method_to_url: [
        eth_call: ConfigHelper.eth_call_url("http://0.0.0.0:12001"),
        eth_getBalance: System.get_env("ETHEREUM_JSONRPC_TRACE_URL") || "http://0.0.0.0:12001",
        trace_replayTransaction: System.get_env("ETHEREUM_JSONRPC_TRACE_URL") || "http://0.0.0.0:12001"
      ],
      http_options: [recv_timeout: timeout, timeout: timeout, hackney: hackney_opts]
    ],
    variant: EthereumJSONRPC.Besu
  ],
  subscribe_named_arguments: [
    transport: EthereumJSONRPC.WebSocket,
    transport_options: [
      web_socket: EthereumJSONRPC.WebSocket.WebSocketClient,
      url: System.get_env("ETHEREUM_JSONRPC_WS_URL"),
      fallback_url: System.get_env("ETHEREUM_JSONRPC_FALLBACK_WS_URL")
    ],
    variant: EthereumJSONRPC.Besu
  ]
