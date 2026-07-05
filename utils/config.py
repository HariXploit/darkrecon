class Config:
    def __init__(self, args):
        self.domain           = args.domain
        self.output           = args.output
        self.threads          = args.threads
        self.skip_screenshots = args.skip_screenshots
        self.skip_amass       = args.skip_amass
        self.timeout          = args.timeout
        self.silent           = args.silent

    def to_dict(self):
        return self.__dict__
