
from jinja2 import Template, Environment
import sys, os
from common.color import WARNING_PREFIX, ERROR_PREFIX, FAIL, WARNING, ENDC, OKGREEN, BOLD, OKBLUE, INFO_PREFIX, OKGREEN
from common.self_check import self_check
from common.util import ask_for_permission
from common.info import show_banner

template_kernel_default = \
  """
  #![enable(implicit_some)]
  (
      runner: QemuKernel((
        qemu_binary: "{{ default_qemu }}",
        kernel: "{{ default_kernel_path }}",
        ramfs: "{{ default_init_ramfs }}",
        debug: false,
      )),
      fuzz: (
          workdir_path: "/tmp/toy_snapshot_workdir",
          bitmap_size: 65536,
          mem_limit: 512,
          time_limit: (
              secs: 0,
              nanos: 80000000,
          ),
          threads: 1,
          thread_id: 0,
          cpu_pin_start_at: 0,
          use_incremental_snapshots: false,
          seed_pattern: "",
          dict: []
      ),
  )
  """

template_vm_default = \
  """
  #![enable(implicit_some)]
  (
      runner: QemuSnapshot((
        qemu_binary: "{{ default_qemu }}",
        hda: "{{ default_vm_hda }}",
        presnapshot: "{{ default_vm_presnapshot }}",
        snapshot_path: DefaultPath,
        debug: false,
      )),
      fuzz: (
          workdir_path: "/tmp/toy_snapshot_workdir",
          bitmap_size: 65536,
          mem_limit: 512,
          time_limit: (
              secs: 0,
              nanos: 80000000,
          ),
        threads: 1,
          thread_id: 0,
          cpu_pin_start_at: 0,
        use_incremental_snapshots: false,
        seed_pattern: "",
        dict: []
      ),
  )
  """


template_kernel = \
  """
  #![enable(implicit_some)]
  (
      include_default_config_path: "{{ default_config_path }}",
      runner: QemuKernel((
          //debug: false,
      )),
      fuzz: (
          workdir_path: "{{ default_workdir }}",
  {% if mem %}
          mem_limit: {{ mem }},
  {% else %}
          //mem_limit: 512,
  {%endif %}
          //use_incremental_snapshots: true,
  {% if seed_path %}
          seed_pattern: "{{ seed_path }}",
  {%else%}
          //seed_pattern: "",
  {%endif %}
          dict: [
  {% if dict_entries %}          {{ dict_entries }}{%endif %}
          ],
  {% if disable_timeouts %}
          time_limit: (
              secs: 0,
              nanos: 0,       
          ),
  {%endif %}
      ),
  )
  """

template_vm = \
  """
  #![enable(implicit_some)]
  (
      include_default_config_path: "{{ default_config_path }}",
      runner: QemuSnapshot((
          //debug: false,
      )),
      fuzz: (
          workdir_path: "{{ default_workdir }}",
  {% if mem %}        mem_limit: {{ mem }},{%endif %}
          //use_incremental_snapshots: true,
  {% if seed_path %}        seed_pattern: "{{ seed_path }}",{%endif %}
          dict: [
  {% if dict_entries %}          {{ dict_entries }}{%endif %}
          ],
  {% if disable_timeouts %}
          time_limit: (
              secs: 0,
              nanos: 0,       
            ),
  {%endif %}
      ),
  )
  """


def get_default_kernel_config(qemu_path, default_kernel_path, default_init_ramfs):
  data = { 
    "default_qemu":  qemu_path,
    "default_kernel_path": default_kernel_path,
    "default_init_ramfs": default_init_ramfs,
  }

  env = Environment(trim_blocks=True)
  template = env.from_string(template_kernel_default)
  return template.render(data)

def get_default_vm_config(qemu_path, default_vm_hda, default_vm_presnapshot):
  data = { 
    "default_qemu":  qemu_path,
    "default_vm_hda": default_vm_hda,
    "default_vm_presnapshot": default_vm_presnapshot,
  }

  env = Environment(trim_blocks=True)
  template = env.from_string(template_vm_default)
  return template.render(data)

def get_config(template_file, default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, disable_timeouts=False):
  data = { 
    "default_config_path":  default_config_path,
    "default_workdir":      default_workdir,
  }

  if mem:
    data['mem'] = mem

  if seed_path:
    data['seed_path'] = seed_path

  if dict_entries:
    data['dict_entries'] = dict_entries

  data['disable_timeouts'] = disable_timeouts

  env = Environment(trim_blocks=True)
  template = env.from_string(template_file)
  return template.render(data)

def gen_kernel_config(default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, disable_timeouts=False):
  return get_config(template_kernel, default_config_path, default_workdir, mem=mem, seed_path=seed_path, dict_entries=dict_entries, disable_timeouts=disable_timeouts)

def gen_vm_config(default_config_path, default_workdir, mem=None, seed_path=None, dict_entries=None, disable_timeouts=False):
  return get_config(template_vm, default_config_path, default_workdir, mem=mem, seed_path=seed_path, dict_entries=dict_entries, disable_timeouts=disable_timeouts)

def to_hex(string):
  try:
    data = bytes(string, "ascii").decode("unicode_escape")
  except:
      data = bytes(string).decode("unicode_escape")

  return "[" + ','.join([str(ord(i)) for i in data]) + "], //%s"%(string)

def convert_dict(path_to_dict_file):
  output = ""
  with open(path_to_dict_file, 'r') as dict_file:
    while True:
      line = dict_file.readline()
      if not line:
        break
      try:
        content = line.split("=")[1].replace("\"", "").replace("\n", "")
        if len(content) > 0:
          output += "%s\n"%(to_hex(content))
      except:
        content = line.replace("\"", "").replace("\n", "")
        if len(content) > 0:
          output += "%s\n"%(to_hex(content))

  return output



def gen_nyx_config(config):

  data = {}
  config_content = ""

  print(config.argument_values["s"])

  if config.argument_values["m"]:
    data["mem"] = config.argument_values["m"]
  
  if config.argument_values["w"]:
    data["workdir"] = config.argument_values["w"]
  else:
    data["workdir"] = "/tmp/toy_snapshot_workdir"

  if config.argument_values["d"]:
    data["dict_entries"] = convert_dict(config.argument_values["d"])
  else:
    data["dict_entries"] = None


  if config.argument_values["s"]:
    data["seed_path"] = os.path.abspath(config.argument_values["s"]) + "/*/*.bin"
  else:
    data["seed_path"] = None

  if config.argument_values["disable_timeouts"]:
    data["disable_timeouts"] = True
  else:
    data["disable_timeouts"] = False

  if config.argument_values["vm_type"] == "Kernel":
    config_content = gen_kernel_config( \
         config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron", \
          data["workdir"], \
          mem=data["mem"], \
          seed_path=data["seed_path"], \
          dict_entries=data["dict_entries"], \
          disable_timeouts=data["disable_timeouts"] \
    )

  elif config.argument_values["vm_type"] == "Snapshot":
    config_content = gen_vm_config( \
          config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron", \
          data["workdir"], \
          mem=data["mem"], \
          seed_path=data["seed_path"], \
          dict_entries=data["dict_entries"], \
          disable_timeouts=data["disable_timeouts"] \
    )
  else:
    raise Exception("Unkown VM Type <%s>"%(config.argument_values["vm_type"]))

  f = open(config.argument_values["share_dir"] + "/config.ron", "w")
  f.write(config_content)
  f.close()


def gen_default_configs(config):
  if config.argument_values["vm_type"] == "Kernel" and not os.path.isfile(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron"):
    print("AUTOGEN default_config_kernel.ron")
    f = open(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_kernel.ron", "w")
    f.write(get_default_kernel_config(config.config_values['QEMU-PT_PATH'], config.config_values['KERNEL'], config.config_values['INIT_RAMFS']))
    f.close()

  if config.argument_values["vm_type"] == "Snapshot" and not os.path.isfile(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron"):
    print("AUTOGEN default_config_vm.ron")

    if config.config_values['DEFAULT_VM_HDA'] == "":
      print("ERROR: DEFAULT_VM_HDA is empty (fix nyx.ini)")
      sys.exit(1)

    if config.config_values['DEFAULT_VM_PRESNAPSHOT'] == "":
      print("ERROR: DEFAULT_VM_PRESNAPSHOT is empty (fix nyx.ini)")
      sys.exit(1)

    f = open(config.config_values['DEFAULT_FUZZER_CONFIG_FOLDER'] + "/default_config_vm.ron", "w")
    f.write(get_default_vm_config(config.config_values['QEMU-PT_PATH'], config.config_values['DEFAULT_VM_HDA'], config.config_values['DEFAULT_VM_PRESNAPSHOT']))
    f.close()


def main():

    from common.config import ConfigGeneratorConfiguration
    config = ConfigGeneratorConfiguration()

    gen_default_configs(config)

    if not self_check():
        return 1

    gen_nyx_config(config)


if __name__ == "__main__":
    main()