defmodule TemplateCompiler do
  @moduledoc """
  Documentation for `TemplateCompiler`.
  """

  @base_path "priv/templater"
  @release_target "target/release/"

  alias TemplateCompiler.Variables

  if match?({:win32, _}, :os.type()) do
    @binary_extension ".exe"
  else
    @binary_extension ""
  end

  @spec new(binary) :: :ok | {:error, {binary, non_neg_integer}} | {:error, [File.posix()]}
  def new(path, variables \\ Variables.default()) do
    :ok = File.mkdir_p(path)

    "#{@base_path}/**/*"
    |> Path.wildcard()
    |> Enum.map(&move_or_generate(&1, path, Variables.to_keyword(variables)))
    |> collect_results()
    |> case do
      :ok ->
        rust_fmt(path)

      e ->
        e
    end
  end

  @spec collect_results([:ok | {:error, File.posix()}]) :: :ok | {:error, [File.posix()]}
  defp collect_results(results) do
    case Enum.reject(results, &(&1 == :ok)) do
      [] -> :ok
      errors -> {:error, Enum.map(errors, &elem(&1, 1))}
    end
  end

  @spec move_or_generate(binary, binary, Access.t()) :: :ok | {:error, File.posix()}
  defp move_or_generate(file_path, path, variables) do
    case String.split(file_path, ".eex") do
      [file_path_without_eex, ""] ->
        render_file(path, file_path, file_path_without_eex, variables)

      _ ->
        if File.regular?(file_path) do
          move_file_over(path, file_path)
        else
          :ok
        end
    end
  end

  @spec render_file(binary, binary, binary, Access.t()) :: :ok | {:error, File.posix()}
  defp render_file(base_path, file_path, file_path_without_eex, variables) do
    new_file = String.replace(file_path_without_eex, @base_path, base_path)

    case new_file |> Path.dirname() |> File.mkdir_p() do
      :ok ->
        out = EEx.eval_file(file_path, variables)
        File.write(new_file, out)

      e ->
        e
    end
  end

  @spec move_file_over(binary, binary) :: :ok | {:error, File.posix()}
  defp move_file_over(base_path, file_path) do
    new_file_destination = String.replace(file_path, @base_path, base_path)

    case new_file_destination |> Path.dirname() |> File.mkdir_p() do
      :ok ->
        File.cp(file_path, new_file_destination)

      e ->
        e
    end
  end

  @spec rust_fmt(binary) :: :ok | {:error, {binary, non_neg_integer}}
  def rust_fmt(path) do
    case System.cmd("cargo", ["fmt"], cd: path) do
      {"", 0} -> :ok
      e -> {:error, e}
    end
  end

  @spec compile(binary) ::
          {:ok, binary} | {:error, {binary, non_neg_integer}} | {:error, :not_found}
  def compile(path) do
    case System.cmd("cargo", ["build", "--release"], cd: path) do
      {"", 0} -> executable_path(path)
      e -> {:error, e}
    end
  end

  @spec executable_path(binary) :: {:ok, binary} | {:error, :not_found}
  def executable_path(base_path) do
    "#{base_path}/#{@release_target}/*"
    |> Path.wildcard()
    |> get_rust_binary()
  end

  @spec recompile(binary) ::
          {:ok, binary} | {:error, {binary, non_neg_integer}} | {:error, [File.posix()]}
  def recompile(path, variables \\ Variables.default()) do
    case new(path, variables) do
      :ok -> compile(path)
      e -> e
    end
  end

  @spec clean_recompile(binary, Variables.t()) ::
          {:ok, nil | binary}
          | {:error, [File.posix()]}
          | {:error, {binary, non_neg_integer}}
          | {:error, atom, binary}
  def clean_recompile(path, variables \\ Variables.default()) do
    case clear(path) do
      {:ok, _} -> recompile(path, variables)
      e -> e
    end
  end

  @spec run(binary) :: {:error, binary} | {:ok, binary}
  def run(file_path) do
    case System.cmd(file_path, []) do
      {out, 0} -> {:ok, out}
      {out, _} -> {:error, out}
    end
  end

  @spec clear(binary) :: {:ok, [binary]} | {:error, atom, binary}
  def clear(path) do
    File.rm_rf(path)
  end

  @spec get_rust_binary([binary]) :: {:ok, binary} | {:error, :not_found}
  defp get_rust_binary(files) do
    case Enum.find(files, nil, &(Path.extname(&1) == @binary_extension && File.regular?(&1))) do
      nil -> {:error, :not_found}
      path -> {:ok, Path.absname(path)}
    end
  end
end
