
class epubSSV:
	doc_partitions = ['cover', 'frontmatter', 'bodymatter', 'backmatter']
	doc_divisions = ['volume', 'part', 'chapter', 'division']
	doc_sections = ['abstract', 'foreword', 'preface', 'prologue',
		'introduction', 'preamble', 'conclusion', 'epilogue', 
		'afterword', 'epigraph']
	doc_navigation = ['toc', 'toc-brief', 'landmarks', 
		'loa', 'loi', 'lot', 'lov']

	doc_ref_sections = ['appendix', 'colophon', 'credits', 'keywords']
	reference_sections = dict(
		indexes = ['index', 'index-headnotes', 'index-legend', 'index-group', 
			'index-entry-list', 'index-entry', 'index-term', 'index-editor-note', 
			'index-locator', 'index-locator-list', 'index-locator-range', 
			'index-xref-preferred', 'index-xref-related', 'index-term-category', 
			'index-term-categories']
		glossaries = ['glossary', 'glossterm', 'glossdef']
		bibliographies = ['bibliography', 'biblioentry']
	)

	preliminary_sections = ['titlepage', 'halftitlepage', 'copyright-page', 
		'seriespage', 'acknowledgments', 'imprint', 'imprimatur', 
		'contributors', 'other-credits', 'errata', 'dedication', 
		'revision-history']

	complementary_content = ['case-study', 'notice', 'pullquote', 'tip']

	titles = ['halftitle', 'fulltitle', 'covertitle', 'title', 'subtitle', 
		'label', 'ordinal', 'bridgehead']

	educational_content = dict(
		learning_objects = ['learning-objective', 'learning-objectives', 
			'learning-outcome', 'learning-outcomes', 'learning-resource', 
			'learning-resources', 'learning-standard', 'learning-standards']
		testing = ['answer', 'answers', 'assessment', 'assessments', 'feedback', 
			'fill-in-the-blank-problem', 'general-problem', 'qna', 
			'match-problem', 'multiple-choice-problem', 'practice', 'question', 
			'practices', 'true-false-problem']
	)
	
	comics = ['panel', 'panel-group', 'balloon', 'text-area', 'sound-area']
	annotations = ['']

	translate = {
		'subchapter': 'division',
		'help': 'tip',
		'marginalia': 'aside',
		'sidebar': 'aside',
		'warning': 'notice'
	}

class epubDocument:
	namespaces = dict(
		html = 'http://www.w3.org/1999/xhtml',
		epub = 'http://www.idpf.org/2007/ops',
		pls = 'https://www.w3.org/2005/01/pronunciation-lexicon',
		ssml = 'https://www.w3.org/2001/10/synthesis'
	)
	doctype4 = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">'
	doctype5 = '<!DOCTYPE html>'

	def __init__(self, title=''):
		self.title = title
		pass
