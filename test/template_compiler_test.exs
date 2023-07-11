defmodule TemplateCompilerTest do
  use ExUnit.Case
  doctest TemplateCompiler

  test "greets the world" do
    assert TemplateCompiler.hello() == :world
  end
end
