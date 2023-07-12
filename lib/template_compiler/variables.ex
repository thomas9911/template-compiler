defmodule TemplateCompiler.Variables do
  @moduledoc """
  Variables that the generated Rust project expects
  """
  defstruct app: "my_templater_1234",
            template_path: "hello.html",
            message: "BIEM!",
            struct: "MyTemplate",
            struct_items: %{name: "String", age: "usize"}

  @type t :: %__MODULE__{
          app: binary,
          message: binary,
          struct: binary,
          struct_items: map,
          template_path: binary
        }

  @spec default() :: t()
  def default do
    %__MODULE__{}
  end

  @spec to_keyword(t()) :: keyword()
  def to_keyword(variables) do
    variables
    |> Map.from_struct()
    |> Enum.to_list()
  end
end
