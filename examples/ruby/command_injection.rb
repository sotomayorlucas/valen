# frozen_string_literal: true

# CWE-78: command injection via standard input / params.
def run
  cmd = gets
  system cmd
end

def run_param
  system params[:cmd] if params[:cmd]
end

def load_config
  data = File.read(params[:path])
  eval(data)
end
