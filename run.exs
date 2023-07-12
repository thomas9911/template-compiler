"tmp/out"
|> TemplateCompiler.recompile()
|> then(fn {:ok, out} -> out end)
|> TemplateCompiler.run()
|> then(fn {:ok, out} -> IO.puts(out) end)
