defmodule Samly.Plug do
  @moduledoc """
  Endpoint-level Plug integration for Samly.

  Add this plug after the body parsers and before the host application's router.
  Requests outside configured Samly paths pass through unchanged.
  """

  @behaviour Plug

  import Plug.Conn

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case find_route(conn) do
      nil -> conn
      routed_conn -> routed_conn |> Samly.Router.call([]) |> halt()
    end
  end

  defp find_route(%{request_path: request_path} = conn) do
    :samly
    |> Application.get_env(:identity_providers, %{})
    |> Enum.find_value(fn {_id, idp} -> route_for_idp(conn, request_path, idp) end)
  end

  defp route_for_idp(conn, request_path, idp) do
    cond do
      uri_path(idp.custom_consume_uri) == request_path ->
        %{conn | path_info: ["sp", "consume", idp.id]}

      uri_path(idp.custom_logout_uri) == request_path ->
        %{conn | path_info: ["sp", "logout", idp.id]}

      under_base_url?(request_path, idp.base_url) ->
        base_path = URI.parse(idp.base_url).path
        relative = String.slice(request_path, String.length(base_path)..-1//1)
        %{conn | path_info: String.split(relative, "/", trim: true)}

      true ->
        nil
    end
  end

  defp under_base_url?(_path, nil), do: false

  defp under_base_url?(request_path, base_url) do
    case URI.parse(base_url).path do
      nil -> false
      "/" -> String.starts_with?(request_path, "/")
      base -> request_path == base or String.starts_with?(request_path, base <> "/")
    end
  end

  defp uri_path(nil), do: nil
  defp uri_path(uri) when is_list(uri), do: uri |> to_string() |> uri_path()
  defp uri_path(uri) when is_binary(uri), do: URI.parse(uri).path
end
