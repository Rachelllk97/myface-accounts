﻿using System.Collections.Generic;
using System.Linq;
using MyFace.Models.Database;
using MyFace.Utilities;
using System;
namespace MyFace.Data
{
    public static class SampleUsers
    {
        public const int NumberOfUsers = 100;

        private static readonly IList<IList<string>> Data = new List<IList<string>>
        {
            new List<string> { "Kania", "Placido", "kplacido0", "kplacido0@qq.com", "Password1" },
            new List<string> { "Scotty", "Gariff", "sgariff1", "sgariff1@biblegateway.com", "Password1" },
            new List<string> { "Colly", "Burgiss", "cburgiss2", "cburgiss2@amazon.co.uk", "Password1" },
            new List<string> { "Barnie", "Percival", "bpercival3", "bpercival3@cmu.edu", "Password1" },
            new List<string> { "Brandon", "Narraway", "bnarraway4", "bnarraway4@trellian.com", "Password1" },
            new List<string> { "Carlos", "Sakins", "csakins5", "csakins5@spiegel.de" , "Password1" },
            new List<string> { "Zeke", "Barkworth", "zbarkworth6", "zbarkworth6@symantec.com", "Password1" },
            new List<string> { "Henrietta", "Verick", "hverick7", "hverick7@adobe.com", "Password1" },
            new List<string> { "Maxine", "Lovett", "mlovett8", "mlovett8@mac.com", "Password1" },
            new List<string> { "Adorne", "Smyth", "asmyth9", "asmyth9@nyu.edu", "Password1" },
            new List<string> { "Roslyn", "O' Scallan", "roscallana", "roscallana@marriott.com", "Password1" },
            new List<string> { "Kalindi", "Bevington", "kbevingtonb", "kbevingtonb@wired.com", "Password1" },
            new List<string> { "Silva", "Cow", "scowc", "scowc@yellowbook.com" , "Password1"},
            new List<string> { "Gnni", "Northage", "gnorthaged", "gnorthaged@lulu.com", "Password1" },
            new List<string> { "Jobi", "Balsom", "jbalsome", "jbalsome@ox.ac.uk", "Password1" },
            new List<string> { "Laurice", "Galgey", "lgalgeyf", "lgalgeyf@usa.gov", "Password1" },
            new List<string> { "Orsola", "Laurant", "olaurantg", "olaurantg@reverbnation.com" , "Password1"},
            new List<string> { "Dante", "Mabley", "dmableyh", "dmableyh@scientificamerican.com" , "Password1"},
            new List<string> { "Shantee", "Guillond", "sguillondi", "sguillondi@gravatar.com" , "Password1" },
            new List<string> { "Mendy", "Djuricic", "mdjuricicj", "mdjuricicj@tuttocitta.it" , "Password1" },
            new List<string> { "Ralph", "Adamovicz", "radamoviczk", "radamoviczk@salon.com" , "Password1"},
            new List<string> { "Zsa zsa", "Goodacre", "zgoodacrel", "zgoodacrel@histats.com" , "Password1" },
            new List<string> { "Fleurette", "Blow", "fblowm", "fblowm@who.int" , "Password1", "Password1" },
            new List<string> { "Zelda", "Pritchett", "zpritchettn", "zpritchettn@wordpress.org" , "Password1"},
            new List<string> { "Kaitlyn", "Filshin", "kfilshino", "kfilshino@so-net.ne.jp" , "Password1" },
            new List<string> { "Aube", "Goneau", "agoneaup", "agoneaup@barnesandnoble.com" , "Password1"},
            new List<string> { "Natala", "Mackrill", "nmackrillq", "nmackrillq@google.es" , "Password1"},
            new List<string> { "Ev", "Wadly", "ewadlyr", "ewadlyr@adobe.com" , "Password1"},
            new List<string> { "Aurora", "Feedham", "afeedhams", "afeedhams@house.gov", "Password1" },
            new List<string> { "Farly", "Chestney", "fchestneyt", "fchestneyt@usda.gov", "Password1" },
            new List<string> { "Chico", "Guilloux", "cguillouxu", "cguillouxu@senate.gov" , "Password1"},
            new List<string> { "Julianna", "Huckstepp", "jhucksteppv", "jhucksteppv@ycombinator.com" , "Password1" },
            new List<string> { "Bev", "Sancto", "bsanctow", "bsanctow@spiegel.de" , "Password1"},
            new List<string> { "Shara", "Jeeves", "sjeevesx", "sjeevesx@behance.net" , "Password1"},
            new List<string> { "Legra", "Jereatt", "ljereatty", "ljereatty@prnewswire.com" , "Password1"},
            new List<string> { "Katey", "Ternouth", "kternouthz", "kternouthz@webmd.com" , "Password1" },
            new List<string> { "Val", "McMenamin", "vmcmenamin10", "vmcmenamin10@noaa.gov", "Password1" },
            new List<string> { "Shannan", "Greenhalf", "sgreenhalf11", "sgreenhalf11@gravatar.com", "Password1" },
            new List<string> { "Sterling", "Fellgate", "sfellgate12", "sfellgate12@surveymonkey.com" , "Password1"},
            new List<string> { "Brina", "Dickens", "bdickens13", "bdickens13@zimbio.com" , "Password1"},
            new List<string> { "Boniface", "McKaile", "bmckaile14", "bmckaile14@jalbum.net" , "Password1"},
            new List<string> { "Vincenty", "Aishford", "vaishford15", "vaishford15@wordpress.org" , "Password1"},
            new List<string> { "Kathye", "Gauford", "kgauford16", "kgauford16@xrea.com" , "Password1"},
            new List<string> { "Chico", "Seelbach", "cseelbach17", "cseelbach17@over-blog.com" , "Password1"},
            new List<string> { "Enoch", "Winsper", "ewinsper18", "ewinsper18@devhub.com" , "Password1"},
            new List<string> { "Brandie", "Welds", "bwelds19", "bwelds19@chicagotribune.com" , "Password1"},
            new List<string> { "Bethanne", "Kerin", "bkerin1a", "bkerin1a@acquirethisname.com" , "Password1"},
            new List<string> { "Margo", "Tompkins", "mtompkins1b", "mtompkins1b@mayoclinic.com" , "Password1"},
            new List<string> { "Allie", "Clever", "aclever1c", "aclever1c@slideshare.net" , "Password1"},
            new List<string> { "North", "Denny", "ndenny1d", "ndenny1d@simplemachines.org" , "Password1"},
            new List<string> { "Ted", "Scorah", "tscorah1e", "tscorah1e@devhub.com" , "Password1"},
            new List<string> { "Leone", "McGow", "lmcgow1f", "lmcgow1f@unblog.fr" , "Password1"},
            new List<string> { "Abbie", "Jannasch", "ajannasch1g", "ajannasch1g@sakura.ne.jp" , "Password1"},
            new List<string> { "Marika", "Dommett", "mdommett1h", "mdommett1h@infoseek.co.jp" , "Password1"},
            new List<string> { "Edith", "Norcop", "enorcop1i", "enorcop1i@behance.net", "Password1" },
            new List<string> { "Ernest", "Baline", "ebaline1j", "ebaline1j@amazon.co.uk" , "Password1"},
            new List<string> { "Rowen", "Dorcey", "rdorcey1k", "rdorcey1k@gravatar.com" , "Password1"},
            new List<string> { "Pasquale", "Surplice", "psurplice1l", "psurplice1l@paypal.com" , "Password1"},
            new List<string> { "Tim", "Dyott", "tdyott1m", "tdyott1m@yellowbook.com" , "Password1"},
            new List<string> { "Tedd", "Connachan", "tconnachan1n", "tconnachan1n@so-net.ne.jp" , "Password1"},
            new List<string> { "Jacquetta", "McClelland", "jmcclelland1o", "jmcclelland1o@nifty.com" , "Password1"},
            new List<string> { "Nelli", "Maund", "nmaund1p", "nmaund1p@myspace.com" , "Password1"},
            new List<string> { "Morie", "Anselmi", "manselmi1q", "manselmi1q@nytimes.com" , "Password1"},
            new List<string> { "Gabie", "Antoniazzi", "gantoniazzi1r", "gantoniazzi1r@dailymail.co.uk" , "Password1"},
            new List<string> { "Menard", "Engelbrecht", "mengelbrecht1s", "mengelbrecht1s@over-blog.com" , "Password1"},
            new List<string> { "Mike", "Tommasetti", "mtommasetti1t", "mtommasetti1t@bluehost.com" , "Password1"},
            new List<string> { "Eldin", "Fredy", "efredy1u", "efredy1u@mozilla.com" , "Password1"},
            new List<string> { "Pris", "McCowen", "pmccowen1v", "pmccowen1v@jalbum.net" , "Password1"},
            new List<string> { "Joey", "Dossettor", "jdossettor1w", "jdossettor1w@webnode.com" , "Password1"},
            new List<string> { "Daisey", "Ogdahl", "dogdahl1x", "dogdahl1x@nyu.edu" , "Password1"},
            new List<string> { "Melanie", "Searle", "msearle1y", "msearle1y@loc.gov" , "Password1"},
            new List<string> { "Beatrix", "MacLise", "bmaclise1z", "bmaclise1z@hugedomains.com" , "Password1"},
            new List<string> { "Missy", "Hillitt", "mhillitt20", "mhillitt20@multiply.com" , "Password1"},
            new List<string> { "Belinda", "Tumielli", "btumielli21", "btumielli21@php.net" , "Password1"},
            new List<string> { "Raynor", "Dupey", "rdupey22", "rdupey22@fc2.com", "Password2" },
            new List<string> { "Inigo", "Heineke", "iheineke23", "iheineke23@ihg.com", "Password2" },
            new List<string> { "Ilaire", "Angric", "iangric24", "iangric24@apache.org", "Password2" },
            new List<string> { "Estel", "Steljes", "esteljes25", "esteljes25@livejournal.com", "Password2" },
            new List<string> { "Lyell", "Ashard", "lashard26", "lashard26@umn.edu", "Password2" },
            new List<string> { "Darren", "Devons", "ddevons27", "ddevons27@economist.com", "Password2" },
            new List<string> { "Warden", "Undrell", "wundrell28", "wundrell28@mozilla.org", "Password2" },
            new List<string> { "Iris", "Langworthy", "ilangworthy29", "ilangworthy29@timesonline.co.uk", "Password2" },
            new List<string> { "Marten", "Minards", "mminards2a", "mminards2a@statcounter.com", "Password2" },
            new List<string> { "Kerry", "Bennion", "kbennion2b", "kbennion2b@spotify.com", "Password2" },
            new List<string> { "Olivette", "Norridge", "onorridge2c", "onorridge2c@cpanel.net", "Password2" },
            new List<string> { "Rosalinde", "Traske", "rtraske2d", "rtraske2d@bbc.co.uk", "Password2" },
            new List<string> { "Gaultiero", "McCard", "gmccard2e", "gmccard2e@utexas.edu", "Password2" },
            new List<string> { "Zonnya", "Capstaff", "zcapstaff2f", "zcapstaff2f@theatlantic.com", "Password2" },
            new List<string> { "Ingelbert", "Sleford", "isleford2g", "isleford2g@qq.com", "Password2" },
            new List<string> { "Nicol", "Nary", "nnary2h", "nnary2h@google.com.hk", "Password2" },
            new List<string> { "Jasun", "Lukianov", "jlukianov2i", "jlukianov2i@blogs.com", "Password2" },
            new List<string> { "Alison", "Durkin", "adurkin2j", "adurkin2j@sitemeter.com", "Password2" },
            new List<string> { "Claudius", "Coronas", "ccoronas2k", "ccoronas2k@tamu.edu", "Password2" },
            new List<string> { "Jakie", "Keener", "jkeener2l", "jkeener2l@princeton.edu", "Password2" },
            new List<string> { "Gilbertine", "Wynett", "gwynett2m", "gwynett2m@epa.gov", "Password2" },
            new List<string> { "Syd", "Cordelle", "scordelle2n", "scordelle2n@blogger.com", "Password2" },
            new List<string> { "Stafford", "Deport", "sdeport2o", "sdeport2o@wix.com", "Password2" },
            new List<string> { "Zacharie", "Perchard", "zperchard2p", "zperchard2p@qq.com", "Password2" },
            new List<string> { "Jane", "Iceton", "jiceton2q", "jiceton2q@lulu.com", "Password2"},
            new List<string> { "Marjy", "Beadell", "mbeadell2r", "mbeadell2r@delicious.com", "Password2"}
        };
        
        public static IEnumerable<User> GetUsers()
        {
            return Enumerable.Range(0, NumberOfUsers).Select(CreateRandomUser);
        }

        private static User CreateRandomUser(int index)
        {
            var saltGenerator = new SaltGenerator();
            var hashGenerator = new HashGenerator();
            byte[] saltArray = saltGenerator.GenerateSalt();
            string salt = Convert.ToBase64String(saltArray);
            string hashedPassword = hashGenerator.GenerateHash(Data[index][4], saltArray);
            //string salt = saltArray.ToString();
            return new User
            {
                FirstName = Data[index][0],
                LastName = Data[index][1],
                Username = Data[index][2],
                Email = Data[index][3],
                ProfileImageUrl = ImageGenerator.GetProfileImage(Data[index][2]),
                CoverImageUrl = ImageGenerator.GetCoverImage(index),
                HashedPassword = hashedPassword,
                Salt = salt
            };
        }
    }
}
