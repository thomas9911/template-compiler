defmodule TemplateCompiler.Runtime do
  alias TemplateCompiler.Index

  @spec run(binary, list) :: {:error, binary} | {:ok, binary}
  def run(file_path, env \\ []) do
    case System.cmd(file_path, [], [into: IO.stream(), env: env]) do
      {out, 0} -> {:ok, out}
      {out, _} -> {:error, out}
    end
  end

  @spec run_linked(binary, list) :: DynamicSupervisor.on_start_child()
  def run_linked(file_path, env \\ []) do
    case Task.Supervisor.start_child(TemplateCompiler.TaskSupervisor, __MODULE__, :run, [file_path, env]) do
      {:ok, _} = result ->
        Index.put(file_path, %{file_path: file_path, env:  env})
        result
      {:ok, _, _} = result ->
        Index.put(file_path, %{file_path: file_path, env:  env})
        result
        e -> e
    end
  end
end
