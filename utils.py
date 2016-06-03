import sys

#
# Simple progress bar implementation
#

class Progress:
    bar_len = 60
    def __init__(self, total, prefix = '', suffix= ''):
        self.count = 0 
        self.total = total
        self.prefix = prefix
        self.suffix = suffix

    def report(self):
        filled_len = int(round(self.bar_len * self.count / float(self.total)))

        percents = round(100.0 * self.count / float(self.total), 1)
        bar = '#' * filled_len + '-' * (self.bar_len - filled_len)
        self.output(bar, percents)
        self.count += 1

    def done(self):
        self.count = self.total
        self.report()
        print ''

    def output(self, bar, percents):
        if self.suffix:
            sys.stdout.write('%s[%s] %s%s ...%s\r' % (self.prefix, bar, percents, '%', self.suffix))
        else:
            sys.stdout.write('%s[%s] %s%s\r' % (self.prefix, bar, percents, '%'))
        sys.stdout.flush()
       
    def get_state(self):
        return {
            'step_len'  : int(round(self.bar_len / float(self.total))),
            'filled_len': int(round(self.bar_len * self.count / float(self.total))),
            'percents'  : round(100.0 * self.count / float(self.total), 1),
        }
    def get_step_bar_info(self):
        return int(round(self.bar_len / float(self.total)))

class Subprogress:
    def __init__(self, parent, total):
        self.parent = parent
        self.total = total
        self.count = 0

    def report(self):
        parent_state = self.parent.get_state()
        filled_len = int(round(parent_state['step_len'] * self.count / float(self.total))) + parent_state['filled_len']
        percents = (round(100 * (self.count / float(self.total)) / (1 / float(self.parent.total)), 1) + parent_state['percents'])
        bar = '#' * filled_len + '-' * (self.parent.bar_len - filled_len)
        self.parent.output(bar, percents)
        self.count += 1

    def done(self):
        self.count = self.total
        self.report()
         
