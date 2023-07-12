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
    variables = [
      app: "my_templater_1234",
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

  defp move_files_over(file_path, path, variables) do
    if file_path |> Path.extname() |> String.ends_with?(".eex") do
      out = EEx.eval_file(file_path, variables)

      new_file = file_path |> String.replace(".eex", "") |> String.replace(@base_path, path)
      :ok = new_file |> Path.dirname() |> File.mkdir_p()
      File.write(new_file, out)
    else
      if File.regular?(file_path) do
        new_file_destination = String.replace(file_path, @base_path, path)
        :ok = new_file_destination |> Path.dirname() |> File.mkdir_p()
        File.copy(file_path, new_file_destination)
      end
    end
  end

  def rust_fmt(path) do
    case System.cmd("cargo", ["fmt"], cd: path) do
      {"", 0} -> :ok
      e -> {:error, e}
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
    new(path)
    compile(path)
  end

  @spec recompile(
          binary
          | maybe_improper_list(
              binary | maybe_improper_list(any, binary | []) | char,
              binary | []
            )
        ) :: any
  def clean_recompile(path) do
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
    case Enum.find(files, nil, &(Path.extname(&1) == @binary_extension && File.regular?(&1))) do
      nil -> nil
      path -> Path.absname(path)
    end
  end
end
