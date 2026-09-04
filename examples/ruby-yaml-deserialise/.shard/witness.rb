# The observation half of this example's entry point.
#
# WHAT IT WATCHES, and why it is not "did the parse succeed". `load_session` is SUPPOSED to parse —
# that is the feature. An entry point firing whenever a document loaded would fire on every benign
# input beside it, Shard would reproduce the finding against those controls, and refuse it. Correctly.
#
# So the marker means one narrow thing: the document caused an OBJECT to be constructed, where the
# session format is plain data. `Psych::DisallowedClass` is what a safe loader raises, and catching it
# is not a finding either — it is the safe loader working.
#
# NOTHING BUT THE MARKER IS PRINTED. The restored session is never echoed.

require "date"

$LOAD_PATH.unshift(File.expand_path("..", __dir__))
require "store"

MARKER = "SHARD_SESSION_OBJECT_CONSTRUCTED"

# What a session value is allowed to be. Anything else means a constructor ran.
PLAIN = [NilClass, TrueClass, FalseClass, Integer, Float, String, Symbol,
         Array, Hash, Date, Time].freeze

def foreign?(value, depth = 0)
  return false if depth > 6
  return true unless PLAIN.any? { |klass| value.is_a?(klass) }

  case value
  when Hash  then value.any? { |k, v| foreign?(k, depth + 1) || foreign?(v, depth + 1) }
  when Array then value.any? { |item| foreign?(item, depth + 1) }
  else false
  end
end

payload = ARGV[0]
exit 2 if payload.nil?

text = File.read(payload)
exit 0 if text.strip.empty?

begin
  session = Store.load_session(text)
rescue StandardError
  # Malformed input, or a safe loader refusing a class. Both are the program working.
  exit 0
end

puts MARKER if foreign?(session)
