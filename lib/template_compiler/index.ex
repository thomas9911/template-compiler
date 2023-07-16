defmodule TemplateCompiler.Index do
    use Agent

    use Agent

    def start_link(_) do
      Agent.start_link(fn -> %{} end, name: __MODULE__)
    end

    def put(key, instance) do
      Agent.update(__MODULE__, fn state -> Map.put(state, key, instance) end)
    end

    def get(key) do
      Agent.get(__MODULE__, fn state -> Map.get(state, key) end)
    end

    def fetch(key) do
      Agent.get(__MODULE__, fn state -> Map.fetch(state, key) end)
    end

    @doc """
    Removes key from state and returns instance
    """
    def remove(key) do
      Agent.get(__MODULE__, fn state -> case state do
          %{^key => instance} -> {instance , Map.delete(state, key)}
          _ -> {nil, state}
        end
      end)
    end
end
