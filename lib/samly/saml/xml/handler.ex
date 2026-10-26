defmodule Samly.SAML.XML.Handler do
  @moduledoc false
  @behaviour Saxy.Handler

  alias Samly.SAML.XML.Namespaces
  alias Saxy.SimpleForm.Handler

  @impl true
  def handle_event(:start_document, prolog, state) do
    case Keyword.get(prolog, :version, "1.0") do
      "1.0" -> {:ok, state}
      _ -> {:stop, {:error, :invalid_xml}}
    end
  end

  def handle_event(:start_element, _data, {_stack, depth, _count, _contexts}) when depth >= 128, do: {:stop, {:error, :xml_too_deep}}

  def handle_event(:start_element, _data, {_stack, _depth, count, _contexts}) when count >= 10_000, do: {:stop, {:error, :xml_too_many_elements}}

  def handle_event(:start_element, {name, attributes} = data, {stack, depth, count, [inherited | _] = contexts}) do
    case Namespaces.validate(name, attributes, inherited) do
      {:ok, namespaces} ->
        {:ok, stack} = Handler.handle_event(:start_element, data, stack)
        {:ok, {stack, depth + 1, count + 1, [namespaces | contexts]}}

      {:error, reason} ->
        {:stop, {:error, reason}}
    end
  end

  def handle_event(:end_element, data, {stack, depth, count, [_current | contexts]}) do
    {:ok, stack} = Handler.handle_event(:end_element, data, stack)
    {:ok, {stack, depth - 1, count, contexts}}
  end

  def handle_event(event, data, {stack, depth, count, contexts}) do
    {:ok, stack} = Handler.handle_event(event, data, stack)
    {:ok, {stack, depth, count, contexts}}
  end
end
