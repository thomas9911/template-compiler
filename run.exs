

TemplateCompiler.recompile("tmp/out") |> TemplateCompiler.run() |> then(fn {:ok, out} ->  IO.puts(out) end)
