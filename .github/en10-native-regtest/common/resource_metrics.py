"""Read counters only for an explicitly owned benchmark PID."""
import sys
if sys.platform=='win32':
 from resource_windows import sample as _sample
elif sys.platform=='darwin':
 from resource_macos import sample as _sample
elif sys.platform.startswith('linux'):
 from resource_linux import sample as _sample
else:
 raise RuntimeError('Unsupported native diagnostic OS')
def sample(pid):
 data=_sample(pid)
 if 'process_start_identity' not in data:
  identity=data.get('process_creation_time_100ns',data.get('process_start_abstime'))
  if identity is None:raise RuntimeError('Missing PID creation identity')
  data['process_start_identity']=str(identity)
 if 'io_byte_semantics' not in data:data['io_byte_semantics']=data.get('io_semantics')
 if not data['io_byte_semantics']:raise RuntimeError('Missing counter I/O semantics')
 if 'pid' in data and data['pid']!=pid:raise RuntimeError('Resource PID mismatch')
 data.setdefault('pid',pid)
 return data
