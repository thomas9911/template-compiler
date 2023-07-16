defmodule TemplateCompiler.Variables do
  @moduledoc """
  Variables that the generated Rust project expects
  """
  defstruct app: "my_templater_1234",
            template_path: "data_table.html.jinja",
            message: "BIEM!",
            struct: "MyTemplate",
            struct_items: %{name: "String", sort: "String"},
            data_url: {:get, "https://raw.githubusercontent.com/thomas9911/csv-generator/main/data/1000.json"}

  @type request_method :: :get | :post
  @type t :: %__MODULE__{
          app: binary,
          message: binary,
          struct: binary,
          struct_items: map,
          template_path: binary,
          data_url: {request_method, binary}
        }

  @spec default() :: t()
  def default do
    %__MODULE__{}
  end

  @spec new(Enumerable.t()) :: t()
  def new(attr) do
    struct(default(), attr) |> IO.inspect()
  end

  @spec to_keyword(t()) :: keyword()
  def to_keyword(variables) do
    variables
    |> Map.from_struct()
    |> Enum.to_list()
  end
end
