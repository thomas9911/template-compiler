# "tmp/out"
# |> TemplateCompiler.recompile()
# |> then(fn {:ok, out} -> out end)
# |> TemplateCompiler.run([{"RUST_LOG", "debug"}])
# |> then(fn {:ok, out} -> IO.puts(out) end)


# "tmp/out2"
# |> TemplateCompiler.recompile(TemplateCompiler.Variables.new(data_url: {:get, "https://raw.githubusercontent.com/thomas9911/csv-generator/main/data/10000.json"}))
# |> then(fn {:ok, out} -> out end)
# |> TemplateCompiler.run([{"SERVER_ADDRESS", "127.0.0.1:4000"}])
# |> then(fn {:ok, out} -> IO.puts(out) end)


"tmp/out"
|> TemplateCompiler.recompile()
|> then(fn {:ok, out} -> out end)
|> TemplateCompiler.run_linked([{"RUST_LOG", "debug"}])
|> IO.inspect()


"tmp/out2"
|> TemplateCompiler.recompile(TemplateCompiler.Variables.new(data_url: {:get, "https://raw.githubusercontent.com/thomas9911/csv-generator/main/data/10000.json"}))
|> then(fn {:ok, out} -> out end)
|> TemplateCompiler.run_linked([{"SERVER_ADDRESS", "127.0.0.1:4000"}])
|> IO.inspect()
