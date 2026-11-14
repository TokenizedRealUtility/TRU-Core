#pragma once
#include "tru_toolbox_guide_catalog.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
namespace tru_core_guide {
using json=nlohmann::json;
inline const json& catalog(){static const json data=json::parse(tru_guide::catalogJson());return data;}
inline std::string lower(std::string s){for(char& c:s)c=static_cast<char>(std::tolower(static_cast<unsigned char>(c)));return s;}
inline std::string text(const json& a){
 std::string out=a.at("title").get<std::string>()+"\nRelated desktop workspace: "+a.at("page").get<std::string>()+"\n\n"+a.at("intro").get<std::string>()+"\n\n";
 if(a.contains("body"))out+=a.at("body").get<std::string>();
 else {int n=0;for(const auto& step:a.at("steps"))out+=std::to_string(++n)+". "+step.get<std::string>()+"\n\n";}
 out+="\nSource: "+a.at("source").get<std::string>()+"\n";
 // Never permit document control characters to act as terminal escape sequences.
 std::string safe;for(unsigned char c:out)if(c=='\n'||c=='\t'||c>=32&&c!=127)safe+=char(c);return safe;
}
inline std::vector<size_t> search(const std::string& query){
 std::string normalized=lower(query);for(char& c:normalized)if(!std::isalnum(static_cast<unsigned char>(c))&&c!='_')c=' ';
 const std::string stop=" how do i a an the to my can you is it what with and for of in on me please tru toolbox ";
 std::istringstream words(normalized);std::vector<std::string> terms;std::string w;
 while(words>>w)if(w.size()>1&&stop.find(" "+w+" ")==std::string::npos)terms.push_back(w);
 std::vector<std::pair<int,size_t>> ranked;
 for(size_t i=0;i<catalog().size();++i){const auto& a=catalog()[i];std::string head=lower(a.at("title").get<std::string>()+" "+a.at("keywords").get<std::string>()),body=lower(text(a));int score=0;
  for(const auto& term:terms){if(head.find(term)!=std::string::npos)score+=4;else if(body.find(term)!=std::string::npos)++score;}
  if(score)ranked.push_back({score,i});
 }
 std::stable_sort(ranked.begin(),ranked.end(),[](auto a,auto b){return a.first>b.first;});
 std::vector<size_t> ids;for(auto p:ranked)ids.push_back(p.second);return ids;
}
inline bool articleIndex(const std::string& s,size_t& i){
 if(s.empty()||s.size()>9||!std::all_of(s.begin(),s.end(),[](unsigned char c){return c>='0'&&c<='9';}))return false;
 auto n=std::stoul(s);if(n<1||n>catalog().size())return false;i=n-1;return true;
}
inline std::vector<std::string> lines(const std::string& value){
 std::istringstream stream(value);std::string line;std::vector<std::string> out;
 while(std::getline(stream,line)){
  if(line.empty()){out.push_back("");continue;}
  // Wrap for narrow terminals; never split a UTF-8 continuation sequence.
  while(line.size()>72){size_t end=72;while(end&&((static_cast<unsigned char>(line[end])&0xc0)==0x80))--end;if(!end)end=72;out.push_back(line.substr(0,end));line.erase(0,end);}
  if(!line.empty())out.push_back(line);
 }return out;
}
inline void run(const std::function<std::string(const std::string&)>& ask,const std::function<void(const std::string&)>& say,const std::function<bool()>& alive){
 std::vector<size_t> result;for(size_t i=0;i<catalog().size();++i)result.push_back(i);
 size_t page=0;constexpr size_t per=12;
 while(alive()){
  std::string listing="TRU GUIDE — OFFLINE DOCUMENTATION\nNo commands are executed. AI explanations are desktop-only.\n\n";
  for(size_t k=page*per;k<std::min(result.size(),(page+1)*per);++k)listing+=std::to_string(result[k]+1)+". "+catalog()[result[k]].at("title").get<std::string>()+"\n";
  if(result.empty())listing+="No documented match. Try a feature name or type list.\n";
  listing+="\nResults "+std::to_string(result.size())+" | page "+std::to_string(page+1)+"\nNUMBER opens article; n/p page; list resets; q exits.\nType a question or search words to find help.";say(listing);
  std::string command=ask("Guide> ");if(!alive()||command=="q"||command=="quit"||command=="exit")return;
  if(command=="n"){if((page+1)*per<result.size())++page;continue;}
  if(command=="p"){if(page)--page;continue;}
  if(command=="list"){result.clear();for(size_t i=0;i<catalog().size();++i)result.push_back(i);page=0;continue;}
  size_t id=0;if(articleIndex(command,id)){
   auto content=lines(text(catalog()[id]));size_t part=0;
   while(alive()){
    std::string view;for(size_t k=part*per;k<std::min(content.size(),(part+1)*per);++k)view+=content[k]+"\n";
    view+="\nArticle "+std::to_string(id+1)+" | page "+std::to_string(part+1)+"/"+std::to_string((content.size()+per-1)/per)+"\nWrapped view; exact text: tru-cli guide read "+std::to_string(id+1)+"\nn next / p previous / b back / q exit guide";say(view);
    auto c=ask("Read> ");if(!alive()||c=="q")return;if(c=="b")break;if(c=="n"&&(part+1)*per<content.size())++part;if(c=="p"&&part)--part;
   }
  }else{if(command.rfind("search ",0)==0)command=command.substr(7);result=search(command);page=0;}
 }
}
inline int command(int argc,char** argv){
 const std::string action=argc>2?argv[2]:"interactive";
 if(action=="interactive"){
  bool active=true;run([&](const std::string& prompt){std::cout<<prompt<<std::flush;std::string s;if(!std::getline(std::cin,s)){active=false;return std::string("q");}return s;},[](const std::string& s){std::cout<<s<<"\n\n";},[&]{return active;});return 0;
 }
 if(action=="list"){for(size_t i=0;i<catalog().size();++i)std::cout<<i+1<<"\t"<<catalog()[i].at("title").get<std::string>()<<"\n";return 0;}
 if(action=="read"&&argc==4){size_t i;if(!articleIndex(argv[3],i)){std::cerr<<"Unknown article number. Use guide list.\n";return 2;}std::cout<<text(catalog()[i]);return 0;}
 if(action=="search"&&argc>=4){std::string q;for(int i=3;i<argc;++i){if(i>3)q+=' ';q+=argv[i];}auto result=search(q);for(size_t i:result)std::cout<<i+1<<"\t"<<catalog()[i].at("title").get<std::string>()<<"\n";if(result.empty())std::cout<<"No documented match.\n";return 0;}
 std::cerr<<"Usage: tru-cli guide [list | search QUESTION | read NUMBER]\n";return 2;
}
}
