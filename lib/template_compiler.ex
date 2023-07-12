defmodule TemplateCompiler do
  @moduledoc """
  Documentation for `TemplateCompiler`.
  """

  @base_path "priv/templater"
  @release_target "target/release/"

  if match?({:win32, _}, :os.type()) do
    @binary_extension ".exe"
  else
    @binary_extension ""
  end

  @spec new(binary) :: :ok | {:error, {any, non_neg_integer}}
  def new(path) do
    variables = [
      app: "my_templater_1234",
      template_path: "hello.html",
      message: "BIEM!",
      struct: "MyTemplate",
      struct_items: %{name: "String", age: "usize"}
    ]

    :ok = File.mkdir_p(path)

    "#{@base_path}/**/*"
    |> Path.wildcard()
    |> Enum.map(&move_files_over(&1, path, variables))

    rust_fmt(path)
  end

  @spec move_files_over(binary, binary, Access.t()) :: any
  defp move_files_over(file_path, path, variables) do
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

  @spec render_file(binary, binary, binary, Access.t()) :: any
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

  @spec move_file_over(binary, binary) :: any
  defp move_file_over(base_path, file_path) do
    new_file_destination = String.replace(file_path, @base_path, base_path)

    case new_file_destination |> Path.dirname() |> File.mkdir_p() do
      :ok ->
        File.copy(file_path, new_file_destination)

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

  @spec compile(binary) :: nil | binary | {binary, non_neg_integer}
  def compile(path) do
    case System.cmd("cargo", ["build", "--release"], cd: path) do
      {"", 0} -> "#{path}/#{@release_target}/*" |> Path.wildcard() |> get_rust_binary()
      e -> e
    end
  end

  @spec recompile(binary) :: nil | binary | {binary, non_neg_integer}
  def recompile(path) do
    new(path)
    compile(path)
  end

  @spec clean_recompile(binary) :: nil | binary | {binary, non_neg_integer}
  def clean_recompile(path) do
    clear(path)
    new(path)
    compile(path)
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

  @spec get_rust_binary([binary]) :: binary | nil
  defp get_rust_binary(files) do
    case Enum.find(files, nil, &(Path.extname(&1) == @binary_extension && File.regular?(&1))) do
      nil -> nil
      path -> Path.absname(path)
    end
  end
end
