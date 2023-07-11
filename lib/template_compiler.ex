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

  def new(path) do
    variables = [app: "my_templater_1234", message: "124"]
    :ok = File.mkdir_p(path)

    "#{@base_path}/**/*"
    |> Path.wildcard()
    |> Enum.map(&move_files_over(&1, path, variables))
  end

  defp move_files_over(file_path, path, variables) do
    if file_path |> Path.extname() |> String.ends_with?(".eex") do
      out = EEx.eval_file(file_path, variables)

      new_file = file_path |> String.replace(".eex", "") |> String.replace(@base_path, path)
      :ok = new_file |> Path.dirname() |> File.mkdir_p()
      File.write(new_file, out)
    else
      if File.regular?(file_path) do
        File.copy(file_path, String.replace(file_path, @base_path, path))
      end
    end
  end

  def compile(path) do
    case System.cmd("cargo", ["build", "--release"], cd: path) do
      {"", 0} -> "#{path}/#{@release_target}/*" |> Path.wildcard() |> get_rust_binary()
      e -> e
    end
  end

  @spec recompile(
          binary
          | maybe_improper_list(
              binary | maybe_improper_list(any, binary | []) | char,
              binary | []
            )
        ) :: any
  def recompile(path) do
    clear(path)
    new(path)
    compile(path)
  end

  def run(file_path) do
    case System.cmd(file_path, []) do
      {out, 0} -> {:ok, out}
      {out, _} -> {:error, out}
    end
  end

  def clear(path) do
    File.rm_rf(path)
  end

  defp get_rust_binary(files) do
    Enum.find(files, nil, &(Path.extname(&1) == @binary_extension && File.regular?(&1)))
  end
end
