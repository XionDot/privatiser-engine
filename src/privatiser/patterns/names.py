"""Name detection: first + last name pairs matched against curated dictionaries."""

import re

from . import PatternHandler, register

# Top ~400 English first names (male + female)
_FIRST_NAMES = {
    # Male
    "aaron", "adam", "alan", "albert", "alexander", "alexis", "alfred", "andrew",
    "anthony", "antonio", "arthur", "austin", "benjamin", "billy", "bobby", "brandon",
    "brian", "bruce", "bryan", "carl", "carlos", "charles", "christian", "christopher",
    "clarence", "claude", "clayton", "clifford", "clinton", "cody", "colin", "corey",
    "craig", "curtis", "dallas", "daniel", "david", "dean", "dennis", "derek",
    "donald", "douglas", "dylan", "edward", "eric", "eugene", "evan", "frank",
    "gary", "george", "gerald", "gilbert", "gordon", "graham", "gregory", "harold",
    "harry", "henry", "howard", "hunter", "jacob", "james", "jason", "jeffrey",
    "jeremy", "jesse", "joel", "john", "johnnie", "johnny", "jonathan", "jordan",
    "joseph", "joshua", "juan", "justin", "keith", "kenneth", "kevin", "kyle",
    "larry", "lawrence", "liam", "lloyd", "logan", "louis", "lucas", "mark",
    "martin", "matthew", "michael", "miguel", "nathan", "nicholas", "noah", "norman",
    "oliver", "oscar", "patrick", "paul", "peter", "philip", "ralph", "randy",
    "raymond", "richard", "robert", "roger", "ronald", "roy", "russell", "ryan",
    "samuel", "scott", "sean", "simon", "stanley", "stephen", "steven", "terry",
    "thomas", "timothy", "todd", "tommy", "tony", "travis", "tyler", "victor",
    "vincent", "walter", "warren", "wayne", "william", "willie", "zachary",
    # Female
    "abigail", "alexis", "alice", "allison", "amanda", "amber", "amy", "andrea",
    "angela", "anna", "annie", "ashley", "audrey", "aurora", "ava", "barbara",
    "betty", "beverly", "brenda", "brittany", "camila", "carol", "carolyn", "catherine",
    "charlotte", "cheryl", "chloe", "christine", "cynthia", "danielle", "deborah",
    "debra", "diana", "diane", "donna", "dorothy", "elena", "eleanor", "elizabeth",
    "ella", "emily", "emma", "evelyn", "faith", "frances", "gabriella", "gloria",
    "grace", "hannah", "harper", "hazel", "heather", "helen", "isabella", "jacqueline",
    "jane", "janet", "janice", "jennifer", "jessica", "joan", "joyce", "judith", "julia",
    "julie", "karen", "katherine", "kathleen", "kelly", "kimberly", "kristin",
    "laura", "layla", "leah", "lillian", "lily", "linda", "lisa", "lucy",
    "luna", "madison", "margaret", "maria", "marilyn", "martha", "mary", "megan",
    "melissa", "michelle", "mia", "natalie", "nicole", "nora", "olivia", "pamela",
    "patricia", "penelope", "rachel", "rebecca", "riley", "rosa", "rose", "ruth",
    "samantha", "sandra", "sara", "sarah", "scarlett", "sharon", "shirley", "skylar",
    "sophia", "stephanie", "stella", "susan", "teresa", "theresa", "tiffany",
    "victoria", "violet", "virginia", "zoey",
}

# Top ~400 English surnames
_LAST_NAMES = {
    "adams", "aguilar", "alexander", "allen", "alvarado", "alvarez", "anderson",
    "andrews", "armstrong", "arnold", "austin", "bailey", "baker", "banks", "barnes",
    "barnett", "barrett", "bell", "bennett", "berry", "bishop", "black", "booth",
    "boyd", "bradley", "brooks", "brown", "bryant", "burke", "burns", "burton",
    "butler", "campbell", "carlson", "carpenter", "carr", "carroll", "carter",
    "castillo", "castro", "chambers", "chapman", "chavez", "chen", "clark",
    "cole", "coleman", "collins", "cook", "cooper", "cox", "crawford", "cunningham",
    "daniels", "davis", "dean", "delgado", "diaz", "dixon", "dominguez", "dunn",
    "duncan", "edwards", "elliott", "ellis", "espinoza", "evans", "fisher",
    "flores", "ford", "foster", "fox", "franklin", "freeman", "fuller", "garcia",
    "gardner", "garrett", "george", "gibson", "gilbert", "gomez", "gonzalez",
    "gordon", "graham", "grant", "graves", "gray", "green", "griffin", "guerrero",
    "gutierrez", "guzman", "hall", "hamilton", "hansen", "harper", "harris",
    "harrison", "hart", "harvey", "hayes", "henderson", "henry", "hernandez",
    "herrera", "hicks", "hill", "hoffman", "holmes", "howard", "howell", "hudson",
    "hughes", "hunt", "hunter", "jackson", "jacobs", "james", "jenkins", "jensen",
    "jimenez", "johnson", "jones", "jordan", "kelly", "kennedy", "kim", "king",
    "knight", "lane", "larson", "lawson", "lee", "lewis", "li", "long",
    "lopez", "lucas", "lynch", "maldonado", "marquez", "marshall", "martin",
    "martinez", "mason", "matthews", "mcdonald", "medina", "mendez", "mendoza",
    "meyer", "miller", "mills", "mitchell", "montgomery", "moore", "morales",
    "moreno", "morgan", "morris", "morrison", "munoz", "murphy", "murray",
    "myers", "nelson", "nguyen", "nichols", "nunez", "obrien", "oliver",
    "olson", "ortega", "ortiz", "owens", "palmer", "park", "patel", "payne",
    "pena", "perez", "perkins", "perry", "peters", "peterson", "phillips",
    "pierce", "porter", "powell", "price", "ramirez", "ramos", "ray", "reed",
    "reid", "reyes", "reynolds", "rice", "richardson", "riley", "rios",
    "rivera", "roberts", "robinson", "rodriguez", "rogers", "romero", "rose",
    "ross", "ruiz", "russell", "ryan", "salazar", "sanchez", "sandoval",
    "santiago", "santos", "schmidt", "scott", "shaw", "silva", "simmons",
    "simpson", "singh", "sims", "smith", "snyder", "soto", "spencer",
    "stephens", "stewart", "stone", "sullivan", "taylor", "thomas", "thompson",
    "tran", "tucker", "turner", "valdez", "vargas", "vasquez", "vega",
    "walker", "wang", "ward", "warren", "watson", "webb", "weber", "weaver",
    "wells", "west", "white", "williams", "williamson", "willis", "wilson",
    "wood", "woods", "wright", "young",
}


def _name_validator(match: re.Match) -> bool:
    """Check both words are in the name dictionaries."""
    first = match.group(1).lower()
    last = match.group(2).lower()
    return first in _FIRST_NAMES and last in _LAST_NAMES


register(
    PatternHandler(
        name="person_name",
        category="ssn",
        regex=re.compile(
            r"\b([A-Z][a-z]{1,14})\s+([A-Z][a-z']{1,19})\b"
        ),
        pseudonym_fn=lambda n: f"[PERSON_{n}]",
        priority=69,
        validator=_name_validator,
    ),
)
