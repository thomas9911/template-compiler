defmodule TemplateCompiler do
  @moduledoc """
  Documentation for `TemplateCompiler`.
  """

  defdelegate new(path), to: TemplateCompiler.Compiler
  defdelegate new(path, variables), to: TemplateCompiler.Compiler
  defdelegate recompile(path), to: TemplateCompiler.Compiler
  defdelegate recompile(path, variables), to: TemplateCompiler.Compiler
  defdelegate clean_recompile(path), to: TemplateCompiler.Compiler
  defdelegate clean_recompile(path, variables), to: TemplateCompiler.Compiler
  defdelegate compile(path), to: TemplateCompiler.Compiler
  defdelegate clear(path), to: TemplateCompiler.Compiler
end
