# A pocket-sized session store with one real defect, kept to a single page.
#
# The defect is `YAML.unsafe_load`. It is there for a reason people actually have: `YAML.load` in
# Psych 4 refuses anything but plain data, so a codebase carrying sessions that contain real objects
# hits an error on upgrade — and `unsafe_load` is the one-word change that makes the error go away.
# It also restores object construction from attacker-controlled text.

require "yaml"

module Store
  # Restore a session from its serialised form.
  def self.load_session(text)
    # THE DEFECT. `unsafe_load` will instantiate whatever the document names.
    YAML.unsafe_load(text)
  end
end
