defmodule Samly.SAML.XML.Handler do
  @moduledoc false
  @behaviour Saxy.Handler

  @impl true
  def handle_event(:start_element, _data, {_stack, depth, _count}) when depth >= 128, do: {:stop, {:error, :xml_too_deep}}

  def handle_event(:start_element, _data, {_stack, _depth, count}) when count >= 10_000, do: {:stop, {:error, :xml_too_many_elements}}

  def handle_event(event, data, {stack, depth, count}) do
    {:ok, stack} = Saxy.SimpleForm.Handler.handle_event(event, data, stack)

    case event do
      :start_element -> {:ok, {stack, depth + 1, count + 1}}
      :end_element -> {:ok, {stack, depth - 1, count}}
      _ -> {:ok, {stack, depth, count}}
    end
  end
end
